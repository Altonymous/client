// Copyright 2019 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package contacts

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/keybase/client/go/encrypteddb"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
)

// ContactCacheStore is used by CachedContactsProvider to store contact cache
// encrypted with device key.
type ContactCacheStore struct {
	encryptedDB *encrypteddb.EncryptedDB
}

func (s *ContactCacheStore) dbKey(uid keybase1.UID) libkb.DbKey {
	return libkb.DbKey{
		Typ: libkb.DBContactResolution,
		Key: fmt.Sprintf("%v", uid),
	}
}

// NewContactCacheStore creates new ContactCacheStore for global context. The
// store is used to securely store cached contact resolutions.
func NewContactCacheStore(g *libkb.GlobalContext) *ContactCacheStore {
	keyFn := func(ctx context.Context) ([32]byte, error) {
		return encrypteddb.GetSecretBoxKey(ctx, g, encrypteddb.DefaultSecretUI,
			libkb.EncryptionReasonContactsLocalStorage, "encrypting contact resolution cache")
	}
	dbFn := func(g *libkb.GlobalContext) *libkb.JSONLocalDb {
		return g.LocalDb
	}
	return &ContactCacheStore{
		encryptedDB: encrypteddb.New(g, dbFn, keyFn),
	}
}

type CachedContactsProvider struct {
	lock sync.Mutex

	Provider ContactsProvider
	Store    *ContactCacheStore
}

var _ ContactsProvider = (*CachedContactsProvider)(nil)

type cachedLookupResult struct {
	ContactLookupResult
	Resolved  bool
	ExpiresAt time.Time
}

type lookupResultCache struct {
	Lookups map[string]cachedLookupResult
	Version struct {
		Major int
		Minor int
	}
}

func makeNewLookupResultCache() (ret lookupResultCache) {
	ret = lookupResultCache{
		Lookups: make(map[string]cachedLookupResult),
	}
	ret.Version.Major = cacheCurrentMajorVersion
	ret.Version.Minor = cacheCurrentMinorVersion
	return ret
}

const cacheCurrentMajorVersion = 1
const cacheCurrentMinorVersion = 1

func cachedResultFromLookupResult(v ContactLookupResult, expires time.Time) cachedLookupResult {
	return cachedLookupResult{
		ContactLookupResult: v,
		Resolved:            true,
		ExpiresAt:           expires,
	}
}

func (c *lookupResultCache) findFreshOrSetEmpty(mctx libkb.MetaContext, key string) (res cachedLookupResult, found bool) {
	now := mctx.G().Clock().Now()
	res, found = c.Lookups[key]
	if !found || now.After(res.ExpiresAt) {
		// Pre-insert to the cache. If Provider.LookupAll does not find these,
		// they will stay in the cache as unresolved, otherwise they are
		// overwritten.

		// Caller is supposed to set proper ExpiresAt value.
		res = cachedLookupResult{Resolved: false, ExpiresAt: now}
		c.Lookups[key] = res
		return res, false
	}
	return res, found
}

func (c *lookupResultCache) cleanup(mctx libkb.MetaContext) {
	now := mctx.G().Clock().Now()
	for key, val := range c.Lookups {
		if now.After(val.ExpiresAt) {
			delete(c.Lookups, key)
		}
	}
}

func (c *CachedContactsProvider) LookupAll(mctx libkb.MetaContext, emails []keybase1.EmailAddress,
	numbers []keybase1.RawPhoneNumber, userRegion keybase1.RegionCode) (res ContactLookupResults, err error) {

	defer mctx.TraceTimed(fmt.Sprintf("CachedContactsProvider#LookupAll(len=%d)", len(emails)+len(numbers)),
		func() error { return nil })()

	res = NewContactLookupResults()
	if len(emails)+len(numbers) == 0 {
		return res, nil
	}

	// This is a rather long-lived lock, because normally it will be held
	// through the entire duration of the lookup, but:
	// - We don't expect this to be called concurrently, or repeatedly, without
	//   user's interaction.
	// - We want to avoid looking up the same assertion multiple times (burning
	//   through the rate limit), while keeping the locking strategy simple.
	c.lock.Lock()
	defer c.lock.Unlock()

	var conCache lookupResultCache
	cacheKey := c.Store.dbKey(mctx.CurrentUID())
	found, cerr := c.Store.encryptedDB.Get(mctx.Ctx(), cacheKey, &conCache)
	if cerr != nil || !found {
		if cerr != nil {
			mctx.Warning("Unable to pull cache: %s", cerr)
		} else if !found {
			mctx.Debug("There was no cache, making a new cache object")
		}
		conCache = makeNewLookupResultCache()
	} else {
		mctx.Debug("Fetched cache, current cache size: %d", len(conCache.Lookups))
		conCache.Version.Major = cacheCurrentMajorVersion
		conCache.Version.Minor = cacheCurrentMinorVersion
	}

	var remainingEmails []keybase1.EmailAddress
	var remainingNumbers []keybase1.RawPhoneNumber

	// Map of keys of new unresolved cache entries, to set ExpireAt value after
	// we do parent provider LookupAll call.
	newUnresolvedEntries := make(map[string]struct{})

	for _, v := range emails {
		key := makeEmailLookupKey(v)
		if cache, found := conCache.findFreshOrSetEmpty(mctx, key); found {
			if cache.Resolved {
				res.Results[key] = cache.ContactLookupResult
			}
		} else {
			remainingEmails = append(remainingEmails, v)
			newUnresolvedEntries[key] = struct{}{}
		}
	}

	for _, v := range numbers {
		key := makePhoneLookupKey(v)
		if cache, found := conCache.findFreshOrSetEmpty(mctx, key); found {
			if cache.Resolved {
				res.Results[key] = cache.ContactLookupResult
			}
		} else {
			remainingNumbers = append(remainingNumbers, v)
			newUnresolvedEntries[key] = struct{}{}
		}
	}

	mctx.Debug("After checking cache, %d emails and %d numbers left to be looked up", len(remainingEmails), len(remainingNumbers))

	if len(remainingEmails)+len(remainingNumbers) > 0 {
		apiRes, err := c.Provider.LookupAll(mctx, remainingEmails, remainingNumbers, userRegion)
		if err == nil {
			now := mctx.G().Clock().Now()
			expiresAt := now.Add(apiRes.ResolvedFreshness)
			for k, v := range apiRes.Results {
				res.Results[k] = v
				conCache.Lookups[k] = cachedResultFromLookupResult(v, expiresAt)
			}
			// Loop through entries that we asked for and find these we did not get
			// resolutions for. Set ExpiresAt now that we know UnresolvedFreshness.
			unresolvedExpiresAt := now.Add(apiRes.UnresolvedFreshness)
			for k := range newUnresolvedEntries {
				val := conCache.Lookups[k]
				if !val.Resolved {
					val.ExpiresAt = unresolvedExpiresAt
					conCache.Lookups[k] = val
				}
			}
		} else {
			mctx.Warning("Unable to call Provider.LookupAll, returning only cached results: %s", err)
		}

		conCache.cleanup(mctx)

		cerr := c.Store.encryptedDB.Put(mctx.Ctx(), cacheKey, conCache)
		if cerr != nil {
			mctx.Warning("Unable to update cache: %s", cerr)
		}
	}

	return res, nil
}

func (c *CachedContactsProvider) FillUsernames(mctx libkb.MetaContext, res []keybase1.ProcessedContact) {
	c.Provider.FillUsernames(mctx, res)
}

func (c *CachedContactsProvider) FillFollowing(mctx libkb.MetaContext, res []keybase1.ProcessedContact) {
	c.Provider.FillFollowing(mctx, res)
}

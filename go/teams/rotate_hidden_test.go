package teams

import (
	"context"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRotateHiddenSelf(t *testing.T) {
	tc, owner, other, _, name := memberSetupMultiple(t)
	defer tc.Cleanup()

	err := SetRoleWriter(context.TODO(), tc.G, name, other.Username)
	require.NoError(t, err)
	team, err := GetForTestByStringName(context.TODO(), tc.G, name)
	require.NoError(t, err)
	require.Equal(t, keybase1.PerTeamKeyGeneration(1), team.Generation())

	secretBefore := team.Data.PerTeamKeySeedsUnverified[team.Generation()].Seed.ToBytes()
	keys1, err := team.AllApplicationKeys(context.TODO(), keybase1.TeamApplication_CHAT)
	require.NoError(t, err)
	require.Equal(t, len(keys1), 1)
	require.Equal(t, keys1[0].KeyGeneration, keybase1.PerTeamKeyGeneration(1))

	err = team.Rotate(context.TODO(), keybase1.RotationType_VISIBLE)
	require.NoError(t, err)
	after, err := GetForTestByStringName(context.TODO(), tc.G, name)
	require.NoError(t, err)
	require.Equal(t, keybase1.PerTeamKeyGeneration(2), after.Generation())
	secretAfter := after.Data.PerTeamKeySeedsUnverified[after.Generation()].Seed.ToBytes()
	require.False(t, libkb.SecureByteArrayEq(secretAfter, secretBefore))
	assertRole(tc, name, owner.Username, keybase1.TeamRole_OWNER)
	assertRole(tc, name, other.Username, keybase1.TeamRole_WRITER)

	keys2, err := after.AllApplicationKeys(context.TODO(), keybase1.TeamApplication_CHAT)
	require.NoError(t, err)
	require.Equal(t, len(keys2), 2)
	require.Equal(t, keys2[0].KeyGeneration, keybase1.PerTeamKeyGeneration(1))
	require.Equal(t, keys1[0].Key, keys2[0].Key)

	for i := 0; i < 3; i++ {
		team, err = GetForTestByStringName(context.TODO(), tc.G, name)
		require.NoError(t, err)
		err = team.Rotate(context.TODO(), keybase1.RotationType_HIDDEN)
		require.NoError(t, err)
		team, err = GetForTestByStringName(context.TODO(), tc.G, name)
		require.NoError(t, err)
		err = team.Rotate(context.TODO(), keybase1.RotationType_VISIBLE)
		require.NoError(t, err)
	}

	team, err = GetForTestByStringName(context.TODO(), tc.G, name)
	require.NoError(t, err)
	keys3, err := team.AllApplicationKeys(context.TODO(), keybase1.TeamApplication_CHAT)
	require.NoError(t, err)
	require.Equal(t, len(keys3), 8)
	require.Equal(t, keys3[0].KeyGeneration, keybase1.PerTeamKeyGeneration(1))
	require.Equal(t, keys1[0].Key, keys3[0].Key)
	require.Equal(t, keys2[1].Key, keys3[1].Key)
}

func TestRotateHiddenOther(t *testing.T) {
	fus, tcs, cleanup := setupNTests(t, 2)
	defer cleanup()

	t.Logf("u0 creates a team (seqno:1)")
	teamName, teamID := createTeam2(*tcs[0])

	t.Logf("U0 adds U1 to the team (2)")
	_, err := AddMember(context.TODO(), tcs[0].G, teamName.String(), fus[1].Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)

	ctx := context.TODO()
	numKeys := 1

	rotate := func(h bool) {
		g := tcs[0].G
		team, err := GetForTestByID(ctx, g, teamID)
		require.NoError(t, err)
		typ := keybase1.RotationType_VISIBLE
		if h {
			typ = keybase1.RotationType_HIDDEN
		}
		err = team.rotate(ctx, typ)
		require.NoError(t, err)
		numKeys++
	}

	checkForUser := func(i int) {
		g := tcs[i].G
		team, err := GetForTestByID(ctx, g, teamID)
		require.NoError(t, err)
		keys, err := team.AllApplicationKeys(context.TODO(), keybase1.TeamApplication_CHAT)
		require.NoError(t, err)
		require.Equal(t, len(keys), numKeys)
	}

	check := func() {
		checkForUser(0)
		checkForUser(1)
	}

	for i := 0; i < 5; i++ {
		rotate(i%2 == 0)
		check()
	}

	mctx1 := libkb.NewMetaContext(ctx, tcs[1].G)
	ch, err := tcs[1].G.GetHiddenTeamChainManager().Load(mctx1, teamID)
	require.NoError(t, err)
	require.Equal(t, keybase1.Seqno(2), ch.RatchetSet.Ratchets[keybase1.RatchetType_MAIN].Triple.Seqno)
}

func TestRotateHiddenOtherFTL(t *testing.T) {
	fus, tcs, cleanup := setupNTests(t, 2)
	defer cleanup()

	t.Logf("u0 creates a team (seqno:1)")
	teamName, teamID := createTeam2(*tcs[0])

	t.Logf("U0 adds U1 to the team (2)")
	_, err := AddMember(context.TODO(), tcs[0].G, teamName.String(), fus[1].Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)

	ctx := context.TODO()
	keyGen := keybase1.PerTeamKeyGeneration(1)

	rotate := func(h bool) {
		g := tcs[0].G
		team, err := GetForTestByID(ctx, g, teamID)
		require.NoError(t, err)
		typ := keybase1.RotationType_VISIBLE
		if h {
			typ = keybase1.RotationType_HIDDEN
		}
		err = team.rotate(ctx, typ)
		require.NoError(t, err)
		keyGen++
	}

	checkForUser := func(i int, forceRefresh bool) {
		mctx := libkb.NewMetaContext(ctx, tcs[i].G)
		arg := keybase1.FastTeamLoadArg{
			ID:            teamID,
			Applications:  []keybase1.TeamApplication{keybase1.TeamApplication_CHAT},
			NeedLatestKey: true,
			ForceRefresh:  forceRefresh,
		}
		team, err := mctx.G().GetFastTeamLoader().Load(mctx, arg)
		require.NoError(t, err)
		require.Equal(t, 1, len(team.ApplicationKeys))
		require.Equal(t, keyGen, team.ApplicationKeys[0].KeyGeneration)
	}

	check := func() {
		checkForUser(0, true)
		checkForUser(1, true)
	}

	for i := 0; i < 5; i++ {
		rotate(i%2 == 0)
		check()
	}

	// Also test the gregor-powered refresh mechanism. We're going to mock out the gregor message for now.
	rotate(true)
	mctx1 := libkb.NewMetaContext(ctx, tcs[1].G)
	tcs[1].G.GetHiddenTeamChainManager().HintLatestSeqno(mctx1, teamID, keybase1.Seqno(4))
	checkForUser(1, false)

	ch, err := tcs[1].G.GetHiddenTeamChainManager().Load(mctx1, teamID)
	require.NoError(t, err)
	require.Equal(t, keybase1.Seqno(2), ch.RatchetSet.Ratchets[keybase1.RatchetType_MAIN].Triple.Seqno)
}

func TestRotateHiddenImplicitAdmin(t *testing.T) {
	tc, _, _, _, _, sub := memberSetupSubteam(t)
	defer tc.Cleanup()
	team, err := GetForTestByStringName(context.TODO(), tc.G, sub)
	require.NoError(t, err)
	require.EqualValues(t, 1, team.Generation())
	err = team.Rotate(context.TODO(), keybase1.RotationType_HIDDEN)
	require.NoError(t, err)
}

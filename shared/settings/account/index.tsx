import * as React from 'react'
import * as Kb from '../../common-adapters'
import * as Styles from '../../styles'
import * as Constants from '../../constants/settings'
import EmailPhoneRow from './email-phone-row'
import * as I from 'immutable'
import {Props as HeaderHocProps} from '../../common-adapters/header-hoc/types'
import flags from '../../util/feature-flags'

export type Props = {
  addedEmail: string | null
  contactKeys: I.List<string>
  hasPassword: boolean
  supersededPhoneNumber?: string
  onClearSupersededPhoneNumber: () => void
  onAddEmail: () => void
  onAddPhone: () => void
  onClearAddedEmail: () => void
  onManageContacts: () => void
  onDeleteAccount: () => void
  onSetPassword: () => void
  onReload: () => void
  waiting: boolean
} & HeaderHocProps

export const SettingsSection = ({children}: {children: React.ReactNode}) => (
  <Kb.Box2 direction="vertical" gap="tiny" fullWidth={true} style={styles.section}>
    {children}
  </Kb.Box2>
)

const EmailPhone = (props: Props) => (
  <SettingsSection>
    <Kb.Box2 direction="vertical" gap="xtiny" fullWidth={true}>
      <Kb.Box2 alignItems="center" direction="horizontal" gap="tiny" fullWidth={true}>
        <Kb.Text type="Header">Email & phone</Kb.Text>
        {props.waiting && <Kb.ProgressIndicator style={styles.progress} />}
      </Kb.Box2>
      <Kb.Text type="BodySmall">
        Secures your account by letting us send important notifications, and allows friends and teammates to
        find you by phone number or email.
      </Kb.Text>
    </Kb.Box2>
    {!!props.contactKeys.size && (
      <Kb.Box2 direction="vertical" style={styles.contactRows} fullWidth={true}>
        {props.contactKeys.map(ck => (
          <EmailPhoneRow contactKey={ck} key={ck} />
        ))}
      </Kb.Box2>
    )}
    <Kb.ButtonBar align="flex-start" style={styles.buttonBar}>
      <Kb.Button mode="Secondary" onClick={props.onAddEmail} label="Add email" small={true} />
      {flags.sbsContacts && (
        <Kb.Button mode="Secondary" onClick={props.onAddPhone} label="Add phone" small={true} />
      )}
    </Kb.ButtonBar>
  </SettingsSection>
)

const Password = (props: Props) => {
  let passwordLabel
  if (props.hasPassword) {
    passwordLabel = Styles.isMobile ? 'Change' : 'Change password'
  } else {
    passwordLabel = 'Set a password'
  }
  return (
    <SettingsSection>
      <Kb.Box2 direction="vertical" gap="xtiny" fullWidth={true}>
        <Kb.Text type="Header">Password</Kb.Text>
        <Kb.Text type="BodySmall">
          Allows you to log out and log back in, and use the keybase.io website.
        </Kb.Text>
      </Kb.Box2>
      <Kb.Box2 direction="horizontal" alignItems="center" fullWidth={true}>
        {props.hasPassword && (
          <Kb.Text type="BodySemibold" style={styles.password}>
            ********************
          </Kb.Text>
        )}
        <Kb.ButtonBar align="flex-start" style={styles.buttonBar}>
          <Kb.Button mode="Secondary" onClick={props.onSetPassword} label={passwordLabel} small={true} />
        </Kb.ButtonBar>
      </Kb.Box2>
    </SettingsSection>
  )
}

const DeleteAccount = (props: Props) => (
  <SettingsSection>
    <Kb.Box2 direction="vertical" gap="xtiny" fullWidth={true}>
      <Kb.Text type="Header">Delete account</Kb.Text>
      <Kb.Text type="BodySmall">
        This can not be undone. You won’t be able to create a new account with the same username.
      </Kb.Text>
    </Kb.Box2>
    <Kb.ButtonBar align="flex-start" style={styles.buttonBar}>
      <Kb.Button
        type="Danger"
        mode="Secondary"
        onClick={props.onDeleteAccount}
        label="Delete account"
        small={true}
      />
    </Kb.ButtonBar>
  </SettingsSection>
)

const ManageContacts = (props: Props) => (
  <SettingsSection>
    <Kb.Box2 direction="vertical" gap="xtiny" fullWidth={true}>
      <Kb.Text type="Header">Manage contacts</Kb.Text>
      <Kb.Text type="BodySmall">Manage importing the contacts on this device.</Kb.Text>
    </Kb.Box2>
    <Kb.ButtonBar align="flex-start" style={styles.buttonBar}>
      <Kb.Button mode="Secondary" onClick={props.onManageContacts} label="Manage contacts" small={true} />
    </Kb.ButtonBar>
  </SettingsSection>
)

const AccountSettings = (props: Props) => (
  <Kb.Reloadable
    onReload={props.onReload}
    reloadOnMount={true}
    waitingKeys={[Constants.loadSettingsWaitingKey]}
  >
    <Kb.ScrollView style={Styles.globalStyles.fullWidth}>
      {props.addedEmail && (
        <Kb.Banner color="yellow" onClose={props.onClearAddedEmail}>
          <Kb.BannerParagraph
            bannerColor="yellow"
            content={`Check your inbox! A verification link was sent to ${props.addedEmail}.`}
          />
        </Kb.Banner>
      )}
      {props.supersededPhoneNumber && (
        <Kb.Banner color="yellow" onClose={props.onClearSupersededPhoneNumber}>
          <Kb.BannerParagraph
            bannerColor="yellow"
            content={`Your unverified phone number ${
              props.supersededPhoneNumber
            } is now associated with another Keybase user.`}
          />
        </Kb.Banner>
      )}
      <Kb.Box2 direction="vertical" fullWidth={true} fullHeight={true}>
        <EmailPhone {...props} />
        <Kb.Divider />
        <Password {...props} />
        {Styles.isMobile && flags.sbsContacts && (
          <>
            <Kb.Divider />
            <ManageContacts {...props} />
          </>
        )}
        <Kb.Divider />
        <DeleteAccount {...props} />
      </Kb.Box2>
    </Kb.ScrollView>
  </Kb.Reloadable>
)

const styles = Styles.styleSheetCreate({
  buttonBar: {
    minHeight: undefined,
    width: undefined,
  },
  contactRows: Styles.platformStyles({
    isElectron: {
      paddingTop: Styles.globalMargins.xtiny,
    },
  }),
  password: {
    ...Styles.padding(Styles.globalMargins.xsmall, 0),
    flexGrow: 1,
  },
  progress: {
    height: 16,
    width: 16,
  },
  section: Styles.platformStyles({
    isElectron: {
      ...Styles.padding(
        Styles.globalMargins.small,
        Styles.globalMargins.mediumLarge,
        Styles.globalMargins.medium,
        Styles.globalMargins.small
      ),
    },
    isMobile: {
      ...Styles.padding(Styles.globalMargins.small, Styles.globalMargins.small, Styles.globalMargins.medium),
    },
  }),
})

export default Kb.HeaderHoc(AccountSettings)

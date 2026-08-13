package com.example.lockdowndpc.policy;

import com.example.lockdowndpc.R;

import java.util.List;

/**
 * Maps system policy values onto localized resources, in the same shape as
 * {@code KioskLabels}.
 *
 * <p>Kept out of {@link SystemPolicyControl} so the decision classes stay free of
 * resource identifiers and remain ordinary JVM-testable code. Every branch is
 * exhaustive on purpose: a control added without a title will not compile.
 */
public final class SystemPolicyLabels {

    private SystemPolicyLabels() {}

    /** The groups the console renders, in order. */
    public enum Section {
        ACCESS(R.string.system_policy_section_access),
        INSTALLS(R.string.system_policy_section_installs),
        NETWORK(R.string.system_policy_section_network),
        DEVICE(R.string.system_policy_section_device);

        private final int titleRes;

        Section(int titleRes) {
            this.titleRes = titleRes;
        }

        public int titleRes() {
            return titleRes;
        }

        /** The controls of this section, in the order an administrator reads them. */
        public List<SystemPolicyControl> controls() {
            return switch (this) {
                case ACCESS -> List.of(
                        SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB,
                        SystemPolicyControl.USB_FILE_TRANSFER);
                case INSTALLS -> List.of(
                        SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS,
                        SystemPolicyControl.APP_STORES_AND_INSTALLERS,
                        SystemPolicyControl.APP_UNINSTALL,
                        SystemPolicyControl.APP_CONTROL_SETTINGS);
                case NETWORK -> List.of(
                        SystemPolicyControl.VPN_CONFIGURATION,
                        SystemPolicyControl.WIFI_CONFIGURATION,
                        SystemPolicyControl.TETHERING,
                        SystemPolicyControl.NETWORK_RESET,
                        SystemPolicyControl.PRIVATE_DNS);
                case DEVICE -> List.of(
                        SystemPolicyControl.ACCOUNT_MODIFICATION,
                        SystemPolicyControl.DATE_AND_TIME,
                        SystemPolicyControl.SAFE_BOOT,
                        SystemPolicyControl.FACTORY_RESET,
                        SystemPolicyControl.USER_AND_PROFILE_CREATION);
            };
        }
    }

    public static int title(SystemPolicyControl control) {
        return switch (control) {
            case DEVELOPER_OPTIONS_AND_ADB ->
                    R.string.system_policy_control_developer_options_and_adb_title;
            case USB_FILE_TRANSFER -> R.string.system_policy_control_usb_file_transfer_title;
            case UNKNOWN_SOURCE_INSTALLS ->
                    R.string.system_policy_control_unknown_source_installs_title;
            case APP_STORES_AND_INSTALLERS ->
                    R.string.system_policy_control_app_stores_and_installers_title;
            case ACCOUNT_MODIFICATION -> R.string.system_policy_control_account_modification_title;
            case VPN_CONFIGURATION -> R.string.system_policy_control_vpn_configuration_title;
            case NETWORK_RESET -> R.string.system_policy_control_network_reset_title;
            case TETHERING -> R.string.system_policy_control_tethering_title;
            case WIFI_CONFIGURATION -> R.string.system_policy_control_wifi_configuration_title;
            case PRIVATE_DNS -> R.string.system_policy_control_private_dns_title;
            case DATE_AND_TIME -> R.string.system_policy_control_date_and_time_title;
            case SAFE_BOOT -> R.string.system_policy_control_safe_boot_title;
            case FACTORY_RESET -> R.string.system_policy_control_factory_reset_title;
            case USER_AND_PROFILE_CREATION ->
                    R.string.system_policy_control_user_and_profile_creation_title;
            case APP_UNINSTALL -> R.string.system_policy_control_app_uninstall_title;
            case APP_CONTROL_SETTINGS -> R.string.system_policy_control_app_control_settings_title;
        };
    }

    /** What turning the control on actually does to the device in front of the operator. */
    public static int consequence(SystemPolicyControl control) {
        return switch (control) {
            case DEVELOPER_OPTIONS_AND_ADB ->
                    R.string.system_policy_control_developer_options_and_adb_consequence;
            case USB_FILE_TRANSFER -> R.string.system_policy_control_usb_file_transfer_consequence;
            case UNKNOWN_SOURCE_INSTALLS ->
                    R.string.system_policy_control_unknown_source_installs_consequence;
            case APP_STORES_AND_INSTALLERS ->
                    R.string.system_policy_control_app_stores_and_installers_consequence;
            case ACCOUNT_MODIFICATION ->
                    R.string.system_policy_control_account_modification_consequence;
            case VPN_CONFIGURATION -> R.string.system_policy_control_vpn_configuration_consequence;
            case NETWORK_RESET -> R.string.system_policy_control_network_reset_consequence;
            case TETHERING -> R.string.system_policy_control_tethering_consequence;
            case WIFI_CONFIGURATION -> R.string.system_policy_control_wifi_configuration_consequence;
            case PRIVATE_DNS -> R.string.system_policy_control_private_dns_consequence;
            case DATE_AND_TIME -> R.string.system_policy_control_date_and_time_consequence;
            case SAFE_BOOT -> R.string.system_policy_control_safe_boot_consequence;
            case FACTORY_RESET -> R.string.system_policy_control_factory_reset_consequence;
            case USER_AND_PROFILE_CREATION ->
                    R.string.system_policy_control_user_and_profile_creation_consequence;
            case APP_UNINSTALL -> R.string.system_policy_control_app_uninstall_consequence;
            case APP_CONTROL_SETTINGS ->
                    R.string.system_policy_control_app_control_settings_consequence;
        };
    }

    public static int outcome(SystemPolicyOutcome outcome) {
        return switch (outcome) {
            case APPLIED -> R.string.system_policy_status_applied;
            case FAILED -> R.string.system_policy_status_failed;
            case UNSUPPORTED -> R.string.system_policy_status_unsupported;
            case REQUESTED -> R.string.system_policy_status_requested;
            case NOT_REQUESTED -> R.string.system_policy_status_not_requested;
        };
    }

    public static int profile(SystemPolicyProfile profile) {
        return profile == SystemPolicyProfile.PRODUCTION
                ? R.string.system_policy_profile_production
                : R.string.system_policy_profile_pilot;
    }
}

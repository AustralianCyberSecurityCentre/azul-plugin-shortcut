"""Parse Microsoft Shortcuts (.LNK) to extract metadata and interesting features."""

from datetime import datetime

from azul_runner import (
    FV,
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from LnkParse3 import lnk_file

from azul_plugin_shortcut.guid import LnkGuid


class AzulPluginShortcut(BinaryPlugin):
    """Parse Microsoft Shortcuts (.LNK) to extract metadata and interesting features."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.03.19"
    SETTINGS = add_settings(
        filter_data_types={"content": ["meta/shortcut/windows"]},
    )
    FEATURES = [
        Feature("link_flag", desc="Shortcut Header Flags", type=FeatureType.String),
        Feature("link_file_flag", desc="Shortcut File Attribute Flags", type=FeatureType.String),
        Feature("link_time_created", desc="Creation time according to shortcut header", type=FeatureType.Datetime),
        Feature("link_time_accessed", desc="Last access time according to shortcut header", type=FeatureType.Datetime),
        Feature(
            "link_time_modified", desc="Last modified time according to shortcut header", type=FeatureType.Datetime
        ),
        Feature("link_window_style", desc="Launch window settings for shortcut", type=FeatureType.String),
        Feature("link_icon_index", desc="Index of icon to use from shortcut icon location", type=FeatureType.Integer),
        Feature("link_icon_location", desc="Location of icon to display for shortcut", type=FeatureType.Filepath),
        Feature("link_description", desc="Description defined in shortcut metadata", type=FeatureType.String),
        Feature("link_working_dir", desc="Working directory defined in shortcut metadata", type=FeatureType.Filepath),
        Feature(
            "link_command_args", desc="Command line arguments defined in shortcut metadata", type=FeatureType.String
        ),
        Feature(
            "link_environment_target",
            desc="Target from link environment variables location block",
            type=FeatureType.String,
        ),
        Feature("link_target", desc="Referenced item from link TargetIDList", type=FeatureType.String),
        Feature("link_target_class", desc="Referenced item class from link TargetIDList", type=FeatureType.String),
        Feature("link_hotkey", desc="Hotkey defined in shortcut header", type=FeatureType.String),
        Feature("link_base_path", desc="Local base path for shortcut", type=FeatureType.Filepath),
        Feature("link_relative_path", desc="Relative path for shortcut", type=FeatureType.Filepath),
        Feature("link_path_suffix", desc="Common path suffix for link shortcut", type=FeatureType.Filepath),
        Feature("link_location", desc="Location of shortcut target", type=FeatureType.String),
        Feature("link_info_drive_serial", desc="Drive serial number from link info", type=FeatureType.String),
        Feature("link_info_volume_label", desc="Volume label from link info", type=FeatureType.String),
        Feature("link_info_drive_type", desc="Drive type from link info", type=FeatureType.String),
        Feature(
            "link_special_folder_id",
            desc="Folder id from special folder location block in shortcut",
            type=FeatureType.Integer,
        ),
        Feature(
            "link_known_folder_id",
            desc="Folder id from known folder location block in shortcut",
            type=FeatureType.String,
        ),
        Feature(
            "link_tracker_machine_id",
            desc="Netbios name from distributed link tracker block in link",
            type=FeatureType.String,
        ),
        Feature(
            "link_tracker_volume_id",
            desc="Droid volume guid from distributed link tracker block",
            type=FeatureType.String,
        ),
        Feature(
            "link_tracker_file_id", desc="Droid file guid from distributed link tracker block", type=FeatureType.String
        ),
        Feature(
            "link_tracker_mac_address", desc="MAC address extracted from link tracker block", type=FeatureType.String
        ),
        Feature(
            "link_tracker_mac_prefix",
            desc="MAC prefix/vendor extracted from link tracker block",
            type=FeatureType.String,
        ),
        Feature(
            "link_tracker_timestamp", desc="Timestamp extracted from link tracker block", type=FeatureType.Datetime
        ),
        Feature(
            "link_properties_format_id", desc="Format id extracted from link properties block", type=FeatureType.String
        ),
        Feature(
            "link_properties_version", desc="Version extraxted from link properties block", type=FeatureType.String
        ),
        Feature("link_network_provider_type", desc="Network provider type from link flags", type=FeatureType.String),
        Feature("link_network_name", desc="Net name from link location info", type=FeatureType.String),
        Feature("link_device_name", desc="Device name from link location info", type=FeatureType.String),
    ]

    def execute(self, job: Job):
        """Process any Windows Shortcut binaries."""
        data = job.get_data()
        lnk = lnk_file(data)
        meta = lnk.get_json(get_all=True)
        header = meta.get("header", {})
        if header.get("guid") != "00021401-0000-0000-C000-000000000046":
            # not valid looking .lnk
            return State.Label.OPT_OUT

        self.features = {}
        # header
        self.set_feature(header, "creation_time", "link_time_created", ts_to_dt)
        self.set_feature(header, "accessed_time", "link_time_accessed", ts_to_dt)
        self.set_feature(header, "modified_time", "link_time_modified", ts_to_dt)
        self.set_feature(header, "icon_index", "link_icon_index", int)
        self.set_feature(header, "windowstyle", "link_window_style")
        if header.get("r_hotkey"):
            self.set_feature(header, "hotkey", "link_hotkey")
        for f in header.get("link_flags", []):
            self.features.setdefault("link_flag", []).append(f)
        for f in header.get("file_flags", []):
            self.features.setdefault("link_file_flag", []).append(f)
        # data
        data = meta.get("data", {})
        self.set_feature(data, "relative_path", "link_relative_path", str)
        self.set_feature(data, "description", "link_description")
        self.set_feature(data, "icon_location", "link_icon_location", str)
        self.set_feature(data, "working_directory", "link_working_dir", str)
        self.set_feature(data, "command_line_arguments", "link_command_args")
        # link_info
        info = meta.get("link_info", {})
        self.set_feature(info, "local_base_path", "link_base_path", str)
        self.set_feature(info, "common_path_suffix", "link_path_suffix", str)
        self.set_feature(info, "common_path_suffix_unicode", "link_path_suffix", str)
        self.set_feature(info, "location", "link_location")
        self.set_feature(info, "network_provider_type", "link_network_provider_type")
        self.set_feature(info, "net_name", "link_network_name")
        self.set_feature(info, "net_name_unicode", "link_network_name")
        self.set_feature(info, "device_name", "link_device_name")
        self.set_feature(info, "device_name_unicode", "link_device_name")
        # link_info.location_info
        info = info.get("location_info", {})
        self.set_feature(info, "drive_serial_number", "link_info_drive_serial")
        self.set_feature(info, "drive_type", "link_info_drive_type")
        self.set_feature(info, "volume_label", "link_info_volume_label")
        self.set_feature(info, "volume_label_unicode", "link_info_volume_label")
        # targets.items
        for x in meta.get("targets", {}).get("items", []):
            if not x:
                continue
            val = x.get("guid", x.get("data", x.get("primary_name", x.get("location"))))
            if not val:
                continue
            self.features.setdefault("link_target", []).append(FV(val, label=x.get("class", "")))
            if not x.get("class"):
                continue
            self.features.setdefault("link_target_class", []).append(x["class"])

        # extra.METADATA_PROPERTIES_BLOCK
        block = meta.get("extra", {}).get("METADATA_PROPERTIES_BLOCK", {}).get("property_store", [])
        if len(block) > 0:
            self.set_feature(block[0], "format_id", "link_properties_format_id")
            self.set_feature(block[0], "version", "link_properties_version")
        # extra.ENVIRONMENT_VARIABLES_LOCATION_BLOCK
        block = meta.get("extra", {}).get("ENVIRONMENT_VARIABLES_LOCATION_BLOCK", {})
        if block.get("target_ansi", "%") != "%":
            self.set_feature(block, "target_ansi", "link_environment_target", str)
        if block.get("target_unicode", "%") != "%":
            self.set_feature(block, "target_unicode", "link_environment_target", str)
        # extra.SPECIAL_FOLDER_LOCATION_BLOCK
        block = meta.get("extra", {}).get("SPECIAL_FOLDER_LOCATION_BLOCK", {})
        self.set_feature(block, "special_folder_id", "link_special_folder_id", int)
        # extra.KNOWN_FOLDER_LOCATION_BLOCK
        block = meta.get("extra", {}).get("KNOWN_FOLDER_LOCATION_BLOCK", {})
        self.set_feature(block, "known_folder_id", "link_known_folder_id")
        # extra.DISTRIBUTED_LINK_TRACKER_BLOCK
        block = meta.get("extra", {}).get("DISTRIBUTED_LINK_TRACKER_BLOCK", {})
        self.set_feature(block, "machine_identifier", "link_tracker_machine_id")
        self.set_feature(block, "droid_volume_identifier", "link_tracker_volume_id")
        self.set_feature(block, "birth_droid_volume_identifier", "link_tracker_volume_id")
        self.set_feature(block, "droid_file_identifier", "link_tracker_file_id")
        self.set_feature(block, "birth_droid_file_identifier", "link_tracker_file_id")
        # decompose the UUID1 identifer
        for x in (block.get("droid_file_identifier"), block.get("birth_droid_file_identifier")):
            if not x:
                continue
            g = LnkGuid(x)
            self.features.setdefault("link_tracker_mac_address", []).append(g.mac)
            self.features.setdefault("link_tracker_timestamp", []).append(g.ts)
            self.features.setdefault("link_tracker_mac_prefix", []).append(FV(g.mac_prefix, label=g.mac_vendor or ""))

        self.add_many_feature_values(self.features)

    def set_feature(self, meta, key, feat, func=str, label=None):
        """Test feature values before setting and handle common transforms."""
        if not meta.get(key):
            return
        self.add_feature_values(feat, FV(func(meta[key]), label=label))


def ts_to_dt(ts):
    """Return the parsed timestamp as a `datetime` object."""
    if isinstance(ts, datetime):
        return ts
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginShortcut)


if __name__ == "__main__":
    main()

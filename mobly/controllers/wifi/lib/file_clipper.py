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

"""The util module for generating excerpts based on a host file."""

import io
import pathlib

from mobly import utils


class ClipFileError(Exception):
  """Raised when trying to conduct invalid operation on FileClipper."""


class FileClipper:
  """The util class for clipping a given host file to multiple fragments.

  This receives a file which is continually being written new content. Users can
  call `clip_new_content` multiple times. Each call will clip the newly appended
  content after the last call as a fragment, and write it to a new file.

  The key point of this class is that it maintains the stream position for all
  `clip_new_content` calls. When `clip_new_content` is called, it reads the
  given file by moving the read stream position to the file end. Then it keeps
  this position unchanged, and the next `clip_new_content` call will start
  reading the file from that position. In this way, each `clip_new_content` call
  only contains the newly appended content after the last call.

  Typical usage:

  .. code-block:: python

    # Preparation
    file_clipper = FileClipper('/tmp/log')

    ... # Append 3 lines to /tmp/log and clip these 3 lines to /tmp/log_clip_1
    file_clipper.clip_new_content('/tmp/log_clip_1')

    ... # Append 5 lines to /tmp/log and clip these 5 lines to /tmp/log_clip_2
    file_clipper.clip_new_content('/tmp/log_clip_2')

    ... # Append 2 lines to /tmp/log and clip these 2 lines to /tmp/log_clip_3
    file_clipper.clip_new_content('/tmp/log_clip_3')

    # Close this clipper and it can no longer clip new contents
    file_clipper.close()
  """

  def __init__(self, source_file_path: pathlib.Path) -> None:
    """Initializes an instance and opens the file object to read the given file.

    Args:
      source_file_path: The host path of the source file to clip.
    """
    self._source_file_path = source_file_path
    self._file_obj_to_read = None

    # We intentionally hide the `open` method from users and open the file
    # object in the constructor, because no use case shall open the file object
    # multiple times.
    self._open()

  def __del__(self):
    self.close()

  def _open(self) -> None:
    """Opens this clipper.

    This method opens the file object to read the given host file.
    """
    utils.create_dir(str(self._source_file_path.parent))
    self._source_file_path.touch()
    self._file_obj_to_read = io.open(
        self._source_file_path, 'r', encoding='utf-8', errors='replace')

  def close(self) -> None:
    """Closes all resources acquired in this instance."""
    if self._file_obj_to_read:
      self._file_obj_to_read.close()
      self._file_obj_to_read = None

  def clip_new_content(self, clip_file_path: pathlib.Path) -> None:
    """Clips the newly appended content and saves it to the given file path.

    Each time this method is called, this will create a clip file based on the
    given source file. The clip contains the content that was written to the
    given source file after the last `clip_new_content` call, or from the start
    of the file.

    Args:
      clip_file_path: The host path to save the created clip.

    Raises:
      ClipFileError: If trying to clip new content after this object is closed.
    """
    if self._file_obj_to_read is None:
      raise ClipFileError(
          'Cannot call `clip_new_content` after this object is closed.')

    with io.open(
        clip_file_path, 'w', encoding='utf-8', errors='replace') as out:
      while True:
        line = self._file_obj_to_read.readline()
        if not line:
          break
        out.write(line)

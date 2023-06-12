#!/usr/bin/env python3

# Copyright (C) 2018-2021  Chris Lalancette <clalancette@gmail.com>

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

# Modified by Modnark

from __future__ import print_function

import argparse
import collections
import os
import sys

import pycdlib

def extract_iso(pathType, startPath, extractTo, isoFile):
    iso = pycdlib.PyCdlib()
    print('Opening %s' % (isoFile))
    iso.open(isoFile)

    if pathType == 'auto':
        if iso.has_udf():
            pathname = 'udf_path'
        elif iso.has_rock_ridge():
            pathname = 'rr_path'
        elif iso.has_joliet():
            pathname = 'joliet_path'
        else:
            pathname = 'iso_path'
    elif pathType == 'rockridge':
        if not iso.has_rock_ridge():
            print('Can only extract Rock Ridge paths from a Rock Ridge ISO')
            return 1
        pathname = 'rr_path'
    elif pathType == 'joliet':
        if not iso.has_joliet():
            print('Can only extract Joliet paths from a Joliet ISO')
            return 2
        pathname = 'joliet_path'
    elif pathType == 'udf':
        if not iso.has_udf():
            print('Can only extract UDF paths from a UDF ISO')
            return 3
        pathname = 'udf_path'
    else:
        pathname = 'iso_path'

    print("Using path type of '%s'" % (pathname))

    root_entry = iso.get_record(**{pathname: startPath})

    dirs = collections.deque([root_entry])
    while dirs:
        dir_record = dirs.popleft()
        ident_to_here = iso.full_path_from_dirrecord(dir_record,
                                                     rockridge=pathname == 'rr_path')
        relname = ident_to_here[len(startPath):]
        if relname and relname[0] == '/':
            relname = relname[1:]
        #print(relname)
        if dir_record.is_dir():
            if relname != '':
                os.makedirs(os.path.join(extractTo, relname))
            child_lister = iso.list_children(**{pathname: ident_to_here})

            for child in child_lister:
                if child is None or child.is_dot() or child.is_dotdot():
                    continue
                dirs.append(child)
        else:
            if dir_record.is_symlink():
                fullpath = os.path.join(extractTo, relname)
                local_dir = os.path.dirname(fullpath)
                local_link_name = os.path.basename(fullpath)
                old_dir = os.getcwd()
                os.chdir(local_dir)
                os.symlink(dir_record.rock_ridge.symlink_path(), local_link_name)
                os.chdir(old_dir)
            else:
                iso.get_file_from_iso(os.path.join(extractTo, relname), **{pathname: ident_to_here})

    iso.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())
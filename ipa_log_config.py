#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Tool for configuring log forwarding on IPA servers and clients
# Copyright (C) 2015  Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys

from argparse import ArgumentParser, RawDescriptionHelpFormatter


def main():
    """Entry-point for script"""

    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
        description='This tool is used to configure log forwarding on IPA '
            'servers\nand clients.',
        epilog=os.path.basename(__file__) + '  Copyright (C) 2015  '
            'Red Hat, Inc.\nThis program comes with ABSOLUTELY NO WARRANTY.\n'
            'This is free software, and you are welcome to redistribute it\n'
            'under certain conditions; see LICENSE file for details.')
    args = parser.parse_args()

    sys.exit(0)


if __name__ == '__main__':
    main()

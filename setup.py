#!/usr/bin/env python

import os
import setuptools
import setuptools.command.build_py

current_dir = os.path.abspath(os.path.dirname(__file__))

setuptools.setup(
    name='rofinetmenu',
    version='0.1',
    description='A network (ethernet and wifi) menu powered by rofi',
    author='Jérôme BOULMIER',
    url='https://github.com/Lomadriel/rofi-net-menu',

    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3'],
    data_files=[
        ('share/doc/rofi-net-menu/examples/', ['examples/config'])
    ],
    package_dir={'':'src'},
    packages=[
        'rofinetmenu'
    ],
    entry_points={
        'console_scripts': [
            'rofi-net-menu = rofinetmenu.netmenu:main'
        ]
    },
    install_requires=['pyxdg']
)

#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='wifu',
    description='A wifi association utility.',
    version='0.1.dev0',
    author='Nathan Wilcox',
    author_email='nejucomo@gmail.com',
    license='GPLv3',
    url='https://github.com/nejucomo/wifu',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'wifu = wifu.main:main',
        ],
    },
    install_requires=[
    ],
)

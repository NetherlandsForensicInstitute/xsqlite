#!/usr/bin/env python

from setuptools import setup

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('xsqlite/VERSION') as f:
    version = f.read().lstrip().rstrip()

setup(
    name='xsqlite',
    version=version,
    author='Netherlands Forensic Institute',
    description="SQLite deleted record recovery tool",
    url='https://github.com/NetherlandsForensicInstitute/xsqlite',
    long_description=readme+"\n\n",
    packages=['xsqlite'],
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python :: 3 :: Only',
        'Intended Audience :: Science/Research',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Environment :: Console'
        ],
    keywords='forensic database sqlite',
    entry_points={
        'console_scripts': ['xsqlite=xsqlite._cmdline:main'],
        },
    install_requires=[
        'bitstring',
        'bigfloat',
        'xlsxwriter',
        'modgrammar'
    ],
    zip_safe=False,
    package_data={
        # include the VERSION file
        'xsqlite': ['VERSION'],
    }
)

#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="moshenasec",
    version="1.0.0",
    description="A comprehensive cybersecurity toolkit for penetration testing",
    author="Polina Moshenets",
    author_email="poshecamo@gmail.com",
    url="https://github.com/poshecamo/moshenasec",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "colorama>=0.4.4",
        "dnspython>=2.1.0",
        "python-whois>=0.7.3",
        "tldextract>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "moshenasec=moshenasec:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)

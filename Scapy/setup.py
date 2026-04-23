"""
Scapy Framework - Professional Offensive and Defensive Cybersecurity Toolkit
"""
from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_file(filename):
    filepath = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    return ""

# Read requirements
def read_requirements():
    filepath = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name='scapy-framework',
    version='1.0.0',
    author='Cristian Cruz',
    author_email='',
    description='Professional offensive and defensive cybersecurity toolkit built with Scapy',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/scapy-framework',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Education',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Environment :: Console',
    ],
    python_requires='>=3.8',
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'scapy-framework=cli.main:app',
        ],
    },
    include_package_data=True,
    package_data={
        '': ['config/*.yaml', 'config/*.json'],
    },
    zip_safe=False,
    keywords='scapy cybersecurity network security pentesting packet-analysis',
)

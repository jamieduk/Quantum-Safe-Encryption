#
# (c) J~Net 2024
#
from setuptools import setup, find_packages

setup(
    name='quantum_safe',
    version='0.1',
    packages=find_packages(),
    description='A simple quantum-safe encryption library based on LWE.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Jay Mee',
    author_email='jamied_uk@hotmail.com',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)


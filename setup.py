import sys, os
import setuptools

version = '0.7.2'

setuptools.setup(
    name='python-whois',
    version=version,
    description="Whois querying and parsing of domain registration information.",
    long_description='',
    install_requires=[
        'future',
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    keywords='whois, python',
    author='Richard Penman',
    author_email='richard.penman@gmail.com',
    url='https://github.com/richardpenman/pywhois',
    license='MIT',
    packages=['whois'],
    package_dir={'whois':'whois'},
    extras_require={
        'better date conversion': ["python-dateutil"]
    },
    test_suite='nose.collector',
    tests_require=['nose', 'simplejson'],
    include_package_data=True,
    zip_safe=False
)

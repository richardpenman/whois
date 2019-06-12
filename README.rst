Goal
====

-  Create a simple importable Python module which will produce parsed
   WHOIS data for a given domain.
-  Able to extract data for all the popular TLDs (com, org, net, ...)
-  Query a WHOIS server directly instead of going through an
   intermediate web service like many others do.
-  Works with Python 2 & 3



Example
=======

.. sourcecode:: python

    >>> import whois
    >>> w = whois.whois('webscraping.com')
    >>> w.expiration_date  # dates converted to datetime object
    datetime.datetime(2013, 6, 26, 0, 0)
    >>> w.text  # the content downloaded from whois server
    u'\nWhois Server Version 2.0\n\nDomain names in the .com and .net 
    ...'

    >>> print w  # print values of all found attributes
    creation_date: 2004-06-26 00:00:00
    domain_name: [u'WEBSCRAPING.COM', u'WEBSCRAPING.COM']
    emails: [u'WEBSCRAPING.COM@domainsbyproxy.com', u'WEBSCRAPING.COM@domainsbyproxy.com']
    expiration_date: 2013-06-26 00:00:00
    ...



Install
=======

Install from pypi:

.. sourcecode:: bash

    $ pip install python-whois

Or checkout latest version from repository:

.. sourcecode:: bash

    $ hg clone https://bitbucket.org/richardpenman/pywhois

Note that then you will need to manually install the futures module, which allows supporting both Python 2 & 3:


.. sourcecode:: bash

    $ pip install futures

Run test cases for python 2 & 3:

.. sourcecode:: bash

    $ python -m unittest discover test
    .............
    ----------------------------------------------------------------------
    Ran 13 tests in 0.812s
    
    OK
    
    $ python3 -m unittest discover test
    .............
    ----------------------------------------------------------------------
    Ran 13 tests in 1.431s
    
    OK

SOCKS Proxy support requirements:

.. sourcecode:: bash

    $ pip install PySocks
    ............
    ---------------------------------------------------------------------
    $ export SOCKS=socksproxy.someplace.com:8080


Problems?
=========

Pull requests are welcome! 

Thanks to the many who have sent patches for additional TLDs. If you want to add or fix a TLD it's quite straightforward. 
See example domains in `whois/parser.py <https://bitbucket.org/richardpenman/pywhois/src/tip/whois/parser.py?at=default&fileviewer=file-view-default>`_

Basically each TLD has a similar format to the following:

.. sourcecode:: python

    class WhoisOrg(WhoisEntry):
    """Whois parser for .org domains
    """
    regex = {
        'domain_name':      'Domain Name: *(.+)',
        'registrar':        'Registrar: *(.+)',
        'whois_server':     'Whois Server: *(.+)',
        ...
    }

    def __init__(self, domain, text):
        if text.strip() == 'NOT FOUND':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text)

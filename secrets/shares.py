#!/usr/bin/env python

import site
site.addsitedir('/System/Library/Frameworks/Python.framework/Versions/2.7/Extras/lib/python/')
import numpy
from scipy import interpolate

import base64
import binascii
import random
from collections import defaultdict
from pprint import pprint

from cryptography.fernet import Fernet


class SplitSecretStore(object):
  """A class capable of splitting and reassembly a secret.

  .. warning::

    This class currently doesn't implement Shamir's secret sharing algorithm
    using finite field arithmetic, which means that an attacker learns
    increasingly more about your secret with each shard they compromise.

  :param shards: The number of shards of the secret to make.
  :param required: The number of shards required to reassemble the secret.

  """

  def __init__(self, shards, required):
    self.shards = shards
    self.required = required

  def polynomial(self, constant, order):
    """Make a polynomial.

    :param constant: The constant polynomial coefficient.
    :param order: The order of the polynomial to create.

    """
    return numpy.polynomial.Polynomial([constant] + [
      random.randint(0, 100) for _ in range(0, order)
    ])

  def split(self, key):
    parts = defaultdict(list)
    for byte in base64.urlsafe_b64decode(key):
      constant = int(binascii.hexlify(byte), 16)
      poly = self.polynomial(constant, self.required)
      for i in range(1, self.shards):
        parts[i].append((i, poly(i)))
    return parts

  def join(self, parts):
    secret = ''
    pieces = zip(*parts)
    for piece in pieces:
      domains = [d for (d, r) in piece]
      ranges = [r for (d, r) in piece]
      poly = interpolate.lagrange(domains, ranges)
      # Convert an integer into a hexidecimal string, less the leading '0x'
      # part added by the `hex` built-in.
      constant = hex(int(poly.coeffs[poly.order]))[2:]
      # Add padding in case it is missing.
      if len(constant) % 2:
        constant = '0' + constant
      secret += binascii.unhexlify(constant)
    return base64.urlsafe_b64encode(secret)


def main():
  key = Fernet.generate_key()
  print key
  ss = SplitSecretStore(shards=10, required=3)
  parts = ss.split(key)
  for shard in parts.keys():
    print shard
    print parts[shard]
  print ss.join([parts[1], parts[3], parts[7], parts[2]])


if __name__ == '__main__':
  main()

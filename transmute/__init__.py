import sys

minver = (3,3,0)

if sys.version_info[0:3] < minver:
   raise ImportError("transmute requires Python version {} or newer.".format('.'.join(('{}'.format(v) for v in minver))))
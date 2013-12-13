import sys

minver = (3,3,0)

if sys.version_info[0:3] < minver:
   raise ImportError("transmute requires Python version {} or newer.".format('.'.join(('{}'.format(v) for v in minver))))

##
# @brief The application version number.
version = (0, 0, '1a')

version_string = '.'.join(str(v) for v in version)
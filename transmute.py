##
# @file transmute.py
# @brief Entry point for the application.
#
# @mainpage
# Generates source code for  network protocol analysis from XML.
# @section Usage
# Transmute is a Python3.x application that accepts an xml specification of a network
# communication protocol, and outputs source code for consumption by other tools.
# Currently, only Wireshark 1.10 is supported, but other applications can be supported
# by adding new plugins. See @ref Design for information about the program design.
# > usage: transmute.py [options] protofile
# positional arguments
# <table>
# <tr><td>name</td><td>summary</td></tr>
# <tr><td>protofile</td><td>The protocol specification XML file to use</td></tr>
# </table>
# optional arguments
# <table>
# <tr><td>short option</td><td>long option</td><td>argument(s)</td><td>summary</td></tr>
# <tr><td>-h</td><td>--help</td><td></td><td>show the help message and exit</td></tr>
# <tr><td>-q</td><td>--quiet</td><td></td><td>Suppress output during processing</td></tr>
# <tr><td>-V</td><td>--verbose</td><td></td><td>Show detailed information during processing</td></tr>
# <tr><td>-VV</td><td>--extra-verbose</td><td></td><td>Show extra detailed information during processing</td></tr>
# <tr><td>-v</td><td>--version</td><td></td><td>show program's version number and exit</td></tr>
# </table>
# wireshark optional arguments
# <table>
# <tr><td>short option</td><td>long option</td><td>argument(s)</td><td>summary</td></tr>
# <tr><td>-ws</td><td>--wireshark</td><td></td><td>Enable wireshark output</td></tr>
# <tr><td></td><td>--wireshark-out</td><td>PATH</td><td>Change the wireshark output folder (default is the current working directory)</td></tr>
# </table>
# @page Design
# @dotfile design.graph High-Level Design
# @section From XML To Anything
# Transmute aims to output more than just Wireshark protocol dissectors in the future. To this end, the application
# is structured around an extensible set of plugins that drive the creation of output files. Roughly, this is how
# Transmute operates:
# -# Load plugins and parse command line arguments
#    - Each plugin is responsible for parsing its command line arguments
# -# Parse XML using the main @ref transmute.Parsing.Parser.Parser "Parser"
#    - Each plugin will have added @ref transmute.Parsing.Parsable.Parsable "Parsables" to the @ref transmute.Parsing.Parser.Parser "Parser" that can decode different tags
# -# Direct fully-parsed entities using the main @ref transmute.Dispatch.Dispatcher.Dispatcher "Dispatcher"
#    - Each plugin will have set up its dispatching behavior according to its arguments
#    - At this point, any plugin with enabled output will generate that output
import argparse
import logging
import transmute
from   sys                import argv
from   os                 import path
from   transmute.Dispatch import Dispatcher
from   transmute.Parsing  import Parser

##
# @brief Configures the application's verbosity.
# @param verbose [in] True if the application should be verbose.
# @param quiet [in] True if the application should be quiet.
def SetVerbosity(quiet, verbose, extra_verbose):
   if quiet:
      logging.basicConfig(level=logging.CRITICAL)
   elif verbose:
      logging.basicConfig(level=logging.INFO)
   elif extra_verbose:
      logging.basicConfig(level=logging.DEBUG)
   else:
      logging.basicConfig(level=logging.WARNING)

##
# @brief The main routine.
# @details Parses arguments and drives the application accordingly.
def main():
   #assign a logger for this routine
   log = logging.getLogger("main")
   args_parser = argparse.ArgumentParser(description="Transform a protocol specification in XML to another representation.", add_help=False)
   #these are the application-level command line arguments
   args_parser.add_argument('protofile',                                                                                                  help="The protocol specification XML file to use.")
   vrbos_group = args_parser.add_mutually_exclusive_group()
   vrbos_group.add_argument('-q',  '--quiet',    default=False,       action='store_true',                                                help="Suppress output during processing.")
   vrbos_group.add_argument('-V',  '--verbose',  default=False,       action='store_true',                                                help="Show detailed information during processing.")
   vrbos_group.add_argument('-VV', '--extra-verbose', default=False,  action='store_true',                                                help="Show extra detailed information during processing.")
   args_parser.add_argument('-v',  '--version',                       action='version',    version='%(prog)s {}'.format(transmute.version_string))
   ns,argv = args_parser.parse_known_args()
   #configure the output mode
   SetVerbosity(ns.quiet, ns.verbose, ns.extra_verbose)
   #set up parser
   log.debug("Initializing parser")
   xml_parser = Parser.Parser()
   #load and register all plugins
   log.debug("Initializing dispatcher for {} folder".format(path.join('transmute', 'plugins')))
   dispatcher = Dispatcher.Dispatcher('plugins')
   dispatcher.register_all(args_parser, xml_parser)
   
   #this here to catch -h/--help arguments (and any others that must only be processed after all plugins are loaded)
   final_args_parser = argparse.ArgumentParser(parents=[args_parser],formatter_class=argparse.RawDescriptionHelpFormatter, usage='%(prog)s [options] protofile')
   final_args_parser.parse_args(argv)
   
   #system initialized, begin parsing
   log.info("Starting parser")
   try:
      with open(ns.protofile, 'r') as protofile:
         for element in xml_parser.parse(protofile):
            #the parser will emit protocol Dispatchables as they are completed
            log.info("Parsing completed for {} {}".format(element.getTag(), element.description.name))
            log.info("Starting validation...")
            element.Validate(None)
            dispatcher.push(element)
   except Parser.ParseError as pe:
      log.warning("Invalid XML Input: {}".format(pe))
   except IOError as ioe:
      log.error("Unable to open file '{}'".format(ns.protofile))
   log.info("Parser stopped.")

if __name__ == '__main__':
   main()

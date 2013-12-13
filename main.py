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
   args_parser.add_argument('-p',  '--protocol', default='proto.xml',                      type=argparse.FileType('r'), dest='protofile', help="The protocol specification XML file to use. (default=\"proto.xml\")")
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
   final_args_parser = argparse.ArgumentParser(parents=[args_parser],formatter_class=argparse.RawDescriptionHelpFormatter)
   final_args_parser.parse_args(argv)
   
   #system initialized, begin parsing
   log.info("Starting parser")
   try:
      for element in xml_parser.parse(ns.protofile):
         #the parser will emit protocol Dispatchables as they are completed
         log.info("Parsing completed for {} {}".format(element.getTag(), element.description.name))
         log.info("Starting validation...")
         element.Validate(None)
         dispatcher.push(element)
   except Parser.ParseError as pe:
      log.warning("Invalid XML Input: {}".format(pe))
   log.info("Parser stopped.")

if __name__ == '__main__':
   main()

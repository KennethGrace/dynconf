#!/usr/bin/env python
#
# DYNCONF: Dynamic Configuration
# Config generator, administrator, and retriever based on Jinja2 templates,
# CSV data, and Netmiko SSH Sessions for Cisco IOS
#
# 2018 Dyntek Services Inc.
# Kenneth J. Grace <kenneth.grace@dyntek.com>
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

VERSION = '1.0'

import sys
import time
from optparse import OptionParser
import os.path
import csv
import getpass
import logging
import logging.config

import multiprocessing as mp
from jinja2 import Environment, FileSystemLoader, StrictUndefined, meta
from netmiko import ConnectHandler, ssh_exception

#Define manual pickling of class object functions
try:
    import copy_reg as cr
except:
    import copyreg as cr
import types
def to_pickle(method):
    fname = method.im_func.__name__
    fobj = method.im_self
    fcls = method.im_class
    return (from_pickle, (fname, fobj, fcls))
def from_pickle(fname, fobj, fcls):
    for fcls in fcls.mro():
        try:
            func = fcls.__dict__[fname]
        except KeyError:
            pass
        else:
            break
    return func.__get__(fobj, fcls)
cr.pickle(types.MethodType, to_pickle, from_pickle)

#Load logging, if logging conf file is present, then load from that
try:
    logging.config.fileConfig('dynconf_logging.conf')
except:
    pass
logger = logging.getLogger('dynconfLogger')

class Template(object):
    def __init__(self, tplstring):
        self.templatepath = os.path.dirname(tplstring)
        self.templatename = os.path.basename(tplstring)
        self.variables = {}
    def get_template_vars(self, ignorevars=[], sort=True, maxnestlevels=100):
        """
        Return a list of all variables found in the template
        Arguments:

            ignorevars  -- a list of variables that are removed from the output
            sort-- True (default) or False if returned list should be sorted
            maxnestlevels -- a positve integer which defines how deep you can
            nest templates with includes
        """
        tplvars = []
        templates = []
        templatesseen = []
        nestlevels = 0
        env = Environment(loader=FileSystemLoader(self.templatepath), undefined=StrictUndefined)
        templates.append(self.templatename)
        templatesseen.append(self.templatename)
        while len(templates) > 0:
            tpl = templates.pop()
            nested = False
            tplsrc = env.loader.get_source(env, tpl)[0]
            ast = env.parse(tplsrc)
            for template in meta.find_referenced_templates(ast):
                if template in templatesseen:
                    raise Exception("Template loop detected: \"{}\" references \"{}\" which was seen earlier".format(tpl, template))
                else:
                    templates.append(template)
                    templatesseen.append(template)
                    nested = True
            for e in meta.find_undeclared_variables(ast):
                if not e in ignorevars:
                    tplvars.append(e)
            if nested and nestlevels >= maxnestlevels:
                raise Exception("Maximum template nesting depth of {} reached in template {}".format(maxnestlevels, template))
            else:
                nestlevels += 1
        if sort:
            return sorted(tplvars)
        else:
            return tplvars
    def set_variables(self, variables, unset=''):
        """
        Set template variables and return a list with unused variables
        """
        tplvars = self.get_template_vars()
        l = []
        for e in tplvars:
            if not e in variables and len(unset) > 0:
                self.variables[e] = unset
            elif not e in variables:
                l.append(e)
            else:
                self.variables[e] = variables[e]
        return l
    def render_template(self):
        env = Environment(loader=FileSystemLoader(self.templatepath), undefined=StrictUndefined)
        tpl = env.get_template(self.templatename)
        return tpl.render(self.variables)

class DynConf(object):
    def __init__(self):
        self.devices = {}
        pass
    def addDevice(self, ip, user, pswd, device_type='cisco_ios', config=''):
        self.devices[ip] = Device(ip, user, pswd, config=config)
    def show(self, ip=None, target='all', key='normal', command=None):
        """ A simple method for outputting the properties of device(s)
        """
        #Phase 1: Target Processing
        target_device_list = self.__findTargets(target=target, ip=ip)
        #Phase 2: Key Processing
        for device in target_device_list:
            device.show(key=key, command=command)

    def validate(self, ip=None, target='all', key=None):
        """ Validate manages a linear low-level validation of Devices
        """
        target_device_list = self.__findTargets(target=target, ip=ip)
        for target in target_device_list:
            target.validate()
    def deploy(self, ip=None, target='all', key=None):
        """ Deploy takes in the cmd arguments and asses the properties of the
            high-level deployment, then manages a multithreaded low-level
            deployment at the device level.
        """
        target_device_list = self.__findTargets(target=target, ip=ip)
        self.__burst(targets=target_device_list, method=Device.deploy)
        for target in target_device_list:
            if target.validated:
                target.confirmation()
                if target.hasErrors:
                    logger.info('\nFail: Error(s) during Administration of Device: {0}'.format(target.ip))
    def commit(self, ip=None, target='all', key='good'):
        """ Commit config to the device through a write-memeory, etc. based on a keyed value.
        """
        target_device_list = self.__findTargets(target=target, ip=ip)
        key_device_list = []
        for target in target_device_list:
            if target == 'ip':
                key_device_list.append(target)
            try:
                if target.hasOutput:
                    if key=='good':
                        if not target.hasErrors:
                            key_device_list.append(target)
                    elif key=='all':
                        key_device_list.append(target)
            except AttributeError:
                pass
        self.__burst(targets=key_device_list, method=Device.commit)
    def inspect(self, ip=None, target='all', command=None):
        """ Retrieve information from a device, using a passed show command
        """
        target_device_list = self.__findTargets(target=target, ip=ip)
        for target in target_device_list:
            target.inspectCommand = command
        self.__burst(targets=target_device_list, method=Device.inspect)
    def super_log(self, ip=None, target='all', key='config_return', command=None):
        """ Using the compiled device logs, create a larger log of all devices.
        """
        target_device_list = self.__findTargets(target=target, ip=ip)
        flag = key
        if key == 'command':
            flag = command
        filename = '{0}.log'.format(flag)
        with open(filename, 'w') as write_file:
            for device in target_device_list:
                try:
                    readname = '{0}_{1}.log'.format(device.ip, flag)
                    with open(readname, 'r') as read_file:
                        data = read_file.read()
                        write_file.write('\n ^^^ BEGIN {0} {1} ^^^\n'.format(device.ip, flag.upper()))
                        write_file.write(data)
                        write_file.write('\n $$$ END {0} {1} $$$\n'.format(device.ip, flag.upper()))
                    logger.info('\nNote: Recorded to \'{0}\' Device: {1}'.format(filename, device.ip))
                except IOError:
                    logger.info('\nNote: No {1} for Device: {0}'.format(device.ip, flag))
    def __findTargets(self, target='nothing', ip=None):
        """ Based on the target parameters create a list of devices, to actually target from within the device list
        """
        target_device_list = []
        if target == 'all':
            target_device_list = self.devices.values()
        elif target == 'ip':
            if ip!=None:
                target_device_list.append(self.devices[ip])
        return target_device_list
    def __burst(self, targets=[], key=None, method=None):
        """ Burst is the custom multiprocessing method for operating on multiple
            devices at a given moment by opening a pool of processes
        """
        proc_cnt = len(targets)
        if proc_cnt >= 100:
            proc_cnt = 99
        try:
            p = mp.Pool(processes=proc_cnt)
            p.map(method, targets)
        except ValueError:
            pass

class Device(object):
    def __init__(self, ip, user, pswd, dev_type='cisco_ios', config='', con=None):
        self.ip = ip
        self.cred = {'user': user, 'pswd': pswd}
        self.dev_type = dev_type
        self.config = config
        self.validated = False
        self.hasErrors = False
    def show(self, key='normal', command=None):
        """ The low-level show for a device.
        """
        print('\nDevice at {0}:'.format(self.ip))
        if key == 'normal':
            try:
                print('Target Configuration:')
                for line in self.config.split('\n'):
                    print('\t{0}'.format(line))
            except AttributeError:
                print('NO CONFIG')
        elif key == 'output':
            try:
                print('Resulting Output:')
                with open(self.ip+'_config_return.log', 'r') as file:
                    confr = file.readlines()
                for line in confr:
                    print('\t{0}'.format(line.strip('\n')))
            except IOError:
                print('\tNO OUTPUT')
        elif key == 'error':
            errs = self.confirmation()
            if len(errs) > 0:
                print('Error Output:')
                for i, err_set in enumerate(errs):
                    print('\tERROR {0}: {1}'.format(i+1, err_set['flag']))
                    for line in err_set['error']:
                        print('\t\t{0}'.format(line.strip('\n')))
            else:
                print('\tNO ERRORS IN OUTPUT')
        elif key == 'command':
            try:
                print('Command Return:')
                with open('{0}_{1}.log'.format(self.ip,command), 'r') as file:
                    confr = file.readlines()
                for line in confr:
                    print('\t{0}'.format(line.strip('\n')))
            except IOError:
                print('\tNO COMMAND OUTPUT')
    def inspect(self):
        """ Reach out and retrieve information from a device.
        """
        connection = self.__connect()
        if connection != None:
            if self.dev_type == 'cisco_ios':
                try:
                    output = self.__administer(connection, cmd=self.inspectCommand, key='expect')
                except AttributeError:
                    logger.error('\nError: No Inspection Command Available on Device: {0}'.format(self.ip))
                else:
                    self.__record(output, flag=self.inspectCommand)
    def validate(self):
        """ This module simply validates the config of the device for later
            deployment.
        """
        self.validated = True
        logger.info('\nNote: Validation performed on Device: {0}'.format(self.ip))
    def commit(self):
        """ Commit the device configuration changes
        """
        #Phase 1: Connection
        connection = self.__connect()
        if connection != None:
            #Phase 2: Administration
            output = self.__administer(connection, cmd='write memory', key='expect')
            #Phase 4: Recording
            self.__record(output, flag='commit_return')
    def deploy(self):
        """ This is the main method for connecting to the device, administering
            config, confirming the administration, and recording the results.
        """
        if self.validated:
            #Phase 1: Connection
            connection = self.__connect()
            if connection != None:
                #Phase 2: Administration
                output = self.__administer(connection, self.config)
                #Phase 4: Recording
                self.__record(output, flag='config_return')
        else:
            logger.info('\nFail: Validation not performed on Device: {0}'.format(self.ip))
    ### INTERNAL MODULES
    def __connect(self):
        conargs = {
            'device_type': self.dev_type,
            'ip': self.ip,
            'username': self.cred['user'],
            'password': self.cred['pswd'],
        }
        connection = None
        try:
            connection = ConnectHandler(**conargs)
        except ssh_exception.NetMikoTimeoutException as e:
            logger.info('\nFail: Connection Timeout from Device: {0}'.format(self.ip))
        except ssh_exception.NetMikoAuthenticationException as e:
            logger.info('\nFail: Bad Auth from Device: {0}'.format(self.ip))
        else:
            logger.info('\nSuccess: Connection Established from Device: {0}'.format(self.ip))
        return connection
    def __administer(self, connection, cmd='!NULL COMMAND', key=None):
        try:
            if key == None:
                out = connection.send_config_set(cmd)
            elif key == 'expect':
                out = connection.send_command_expect(cmd)
        except AttributeError:
            out = 'NO OUTPUT'
        else:
            logger.info('\nNote: Administration Performed from Device: {0}'.format(self.ip))
        finally:
            return out
    def confirmation(self):
        try:
            out_errors = []
            with open(self.ip+'_config_return.log', 'r') as file:
                confr = file.read()
                self.hasOutput = True
        except IOError:
            self.hasOutput = False
        else:
            output = confr.split('\n')
            out_errors = []
            if 'NO OUTPUT' not in output:
                if self.dev_type == 'cisco_ios':
                    i=0
                    while i < len(output):
                        errSet = {}
                        # Input Errors
                        if '%' in output[i] and '^' in output[i]:
                            errSet['error'] = output[i-2:i+1]
                            errSet['flag'] = 'Invalid Input'
                            out_errors.append(errSet)
                            i+=2
                        # Notice Error
                        elif output[i].startswith('%'):
                            errSet['error'] = output[i-1:i+1]
                            errSet['flag'] = 'Notice'
                            out_errors.append(errSet)
                            i+=2
                        # Warning Error
                        elif output[i].startswith('Warning:'):
                            errSet['error'] = output[i-1:i+2]
                            errSet['flag'] = 'Warning'
                            out_errors.append(errSet)
                            i+=2
                        i+=1
            if len(out_errors) > 0:
                self.hasErrors = True
        return out_errors
    def __record(self, output='NO OUTPUT', flag=''):
        filename = '{0}_{1}.log'.format(self.ip, flag)
        try:
            if output != 'NO OUTPUT':
                with open(filename, 'w') as file:
                    file.write(output)
                logger.info('\nNote: {0} Recorded Device: {1}\nSee "{2}" for output'.format(flag, self.ip, filename))
        except AttributeError as e:
            logger.error('\nError: No Output to record from Device: {0}'.format(self.ip))

class CLI(object):
    """This is the object for interacting with the commandline utility of Dynconf"""
    def __init__(self, username=None, password=None):
        print('\n### Welcome to DYNCONF V{0} ###\n'.format(VERSION))
        if username == None:
            self.username = ''
            while len(self.username) <= 0:
                self.username = input('Username: ')
        else:
            self.username = username
        if password == None:
            self.password = getpass.getpass('{0} password: '.format(self.username))
        else:
            self.password = password
    class Util(object):
        """Util is an object for command tree navigation."""
        def __init__(self, this, description, tree=None, method=None, is_key=False, is_target=False, multi=False):
            self.this = this
            self.description = description
            self.variable = False
            if this.startswith('<') and this.endswith('>'):
                self.variable = True
            self.terminate = True
            if tree != None:
                self.terminate = False
                self.tree = tree
            self.operable = False
            if method != None:
                self.operable = True
                self.method = method
            self.is_key = is_key
            self.is_target = is_target
            self.multi = multi
        def showTree(self):
            if not self.terminate:
                for u in self.tree:
                    row = [u.this, u.description]
                    print(''.join(line.ljust(16) for line in row))
            else:
                row = ['<return>', 'Press Enter']
                print(''.join(line.ljust(16) for line in row))
        def validValue(self, val):
            """
            Checks if a passed value matches the type and format neccesary for the variable util
            """
            if self.this == '<string>':
                return str == type(val)
            elif self.this == '<ip>':
                ip_oct = val.split('.')
                validOct = 0
                if len(ip_oct) == 4:
                    for oct in ip_oct:
                        if oct.isdigit():
                            if 256 > int(oct) and int(oct) >= 0:
                                validOct+=1
                return validOct == 4
            elif self.this == '<command>':
                return True
    def recieve(self, prompt, default):
        r = input('{0} [{1}]: '.format(prompt, default))
        if len(r) <= 0:
            r = default
        return r
    def establishUtility(self, manager):
        showKeyUtil = [
            CLI.Util('<command>', 'Show command results', method=manager.show, is_key=True, multi=True),
            CLI.Util('output', 'Show administration results', method=manager.show, is_key=True),
            CLI.Util('error', 'Show administration errors', method=manager.show, is_key=True)
        ]
        getKeyUtil = [
            CLI.Util('<command>', 'Show command to send to machine.', method=manager.inspect, multi=True)
        ]
        self.utilTree = CLI.Util('meta', 'meta', tree=[
            CLI.Util('show', 'Show the properties of a Device(s)', tree=[
                CLI.Util('<ip>', 'IPv4 Address', method=manager.show, tree=showKeyUtil, is_target=True),
                CLI.Util('all', 'Show the properties of all Devices', method=manager.show, tree=showKeyUtil, is_target=True),
            ]),
            CLI.Util('validate', 'Get the running-config for a Device(s)', tree=[
                CLI.Util('<ip>', 'IPv4 Address', method=manager.validate, is_target=True),
                CLI.Util('all', 'Get the running-config for all Devices', method=manager.validate, is_target=True)
            ]),
            CLI.Util('log', 'Create a log of device logs', tree=[
                CLI.Util('<command>', 'Log for a sent command', method=manager.super_log, is_key=True, multi=True),
                CLI.Util('config_return', 'Log for Configuration Returns', method=manager.super_log, is_key=True),
                CLI.Util('config', 'Log for Runnning Configurations', method=manager.super_log, is_key=True),
                CLI.Util('commit_return', 'Log for Commit Returns', method=manager.super_log, is_key=True)
            ]),
            CLI.Util('deploy', 'Deploy config to a Device(s)', tree=[
                CLI.Util('<ip>', 'IPv4 Address', method=manager.deploy, is_target=True),
                CLI.Util('all', 'Deploy config to all Devices', method=manager.deploy, is_target=True)
            ]),
            CLI.Util('commit', 'Commit config to a Device(s)', tree=[
                CLI.Util('<ip>', 'IPv4 Address', method=manager.commit, is_target=True),
                CLI.Util('all', 'Commit config to all Devices', tree=[
                    CLI.Util('good', 'Commit only to good devices', method=manager.commit, is_key=True),
                    CLI.Util('all', 'Commit all devices', method=manager.commit, is_key=True)
                ], is_target=True)
            ]),
            CLI.Util('get', 'Get the running-config for a Device(s)', tree=[
                CLI.Util('<ip>', 'IPv4 Address', tree=getKeyUtil, is_target=True),
                CLI.Util('all', 'Get the running-config for all Devices', tree=getKeyUtil, is_target=True)
            ]),
            CLI.Util('end', 'Terminate DynConf', method=self.terminate)
        ])
        self.active = True
    def utility(self):
        """ Using utils as building blocks, this traverses and operates on the Util tree
        """
        cmdline = input('{0}@dynconf# '.format(self.username))
        if len(cmdline) > 0:
            cmd = cmdline.split(' ')
            kwargs = {}
            cur_util = self.utilTree
            err = False
            i=0
            while not cur_util.terminate and i < len(cmd):
                if cmd[i] != '?':
                    #First, check to see if the cmd matches a non-var util
                    found = False
                    for u in cur_util.tree:
                        if not u.variable:
                            if cmd[i] == u.this:
                                cur_util = u
                                if cur_util.is_target:
                                    kwargs['target'] = cmd[i]
                                found = True
                                break
                    #If not found, then Secondly check for variable matches
                    if not found:
                        for u in cur_util.tree:
                            if u.variable:
                                varcmd = cmd[i]
                                if u.multi:
                                    for w in cmd[i+1:]:
                                        varcmd += (' '+w)
                                if u.validValue(varcmd):
                                    kwargs[u.this.strip('<').strip('>')] = varcmd
                                    cur_util = u
                                    if cur_util.is_target:
                                        kwargs['target'] = u.this.strip('<').strip('>')
                                    found = True
                                    break
                                else:
                                    print('\nBad Value: \'{0}\''.format(varcmd))
                                    err = True
                    if not found and not err:
                        print('\nInvalid Command: \'{0}\''.format(cmd[i]))
                        err = True
                if err:
                    break
                i+=1
            if not err:
                if cmd[-1] == '?':
                    r = cur_util.showTree()
                else:
                    if cur_util.operable == True:
                        if cur_util.is_key:
                            kwargs['key'] = cur_util.this.strip('<').strip('>')
                        try:
                            r = cur_util.method(**kwargs)
                        except OSError:
                            pass
                    else:
                        print('\nIncomplete Command: Consider Using \'?\'')
                        r = 0
                return r
    def acknowledge(self, prompt):
        r = input('{0} [yes/no]'.format(prompt))
        if len(r) <= 0:
            r = 'no'
        return r.lower() == 'yes'
    def terminate(self):
        self.active = False

###########################
####                    ###
####    MAIN  MODULE    ###
####                    ###
###########################

if __name__ == '__main__':
    try:
        def operate(manager, options):
            t = 'all'
            ip = None
            if options.ipaddress != None:
                t = 'ip'
                ip = options.ipaddress
            manager.validate(ip=ip, target=t)
            if not options.getcommand:
                manager.deploy(ip=ip, target=t)
                logkey = 'config_return'
                cmd = None
            else:
                manager.inspect(ip=ip, target=t, command=options.getcommand)
                logkey = 'command'
                cmd = options.getcommand
            if options.writetarget != None:
                manager.commit(ip=ip, target=t, key=options.writetarget)
                manager.super_log(ip=ip, target=t, key='commit_return')
            manager.super_log(ip=ip, target=t, key=logkey, command=cmd)
            if options.showcmd != None:
                manager.show(ip=ip, target=t, key=options.showcmd)
        def get_vars_from_csv(filename):
            """
            READ A CSV AND RETURN A LIST OF DICTS OF THE ELEMENTS KEYED BY THE
            COLUMN NAME
            """
            l = []
            with open(filename, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    l.append(row)
            return l
        #Define options for function call
        optparser = OptionParser(usage="usage: %prog [options]")
        optparser.add_option('-u', '--username', dest='username',
                             help='Default username for device connections')
        optparser.add_option('-p', '--password', dest='password',
                             help='Default password for device connections')
        optparser.add_option('-t', '--template', dest='template',
                             help='Read variables into a jinja2 template')
        optparser.add_option('-c', '--csv', dest='inputcsv',
                             help='Read variables from a CSV file')
        optparser.add_option('-v', '--validate', dest='validate',
                             help='Number of config validations to perform')
        optparser.add_option('-i', '--ipaddress', dest='ipaddress',
                             help='Single device to perform config on')
        optparser.add_option('-w', '--writetarget', dest='writetarget',
                             help='Write config on completion to keyed devices (good, all)')
        optparser.add_option('-s', '--show', dest='showcmd',
                             help='Show output of target devices by key (normal, output, error)')
        optparser.add_option('-G', '--get', dest='getcommand',
                             help='Show command to send to machine')
        optparser.add_option('-I', '--interactive', action='store_true', dest='interactive',
                             default=False, help='Enable enhanced operation mode')
        optparser.add_option('-Q', '--quiet', action='store_true', dest='quiet',
                             default=False, help='Hide logging')
        (options, args) = optparser.parse_args()
        if options.quiet:
            logger.setLevel(logging.WARNING)
        # Prepare the Commander for program execution
        manager = DynConf()
        #Prepare the CLI, pass username/password
        kwargs = {}
        if options.username:
            kwargs['username'] = options.username
        if options.password:
            kwargs['password'] = options.password
        commandLine = CLI(**kwargs)
        # Render the Template for Use, if neccesary
        if not options.getcommand:
            tplfilename = ''
            if options.template:
                tplfilename = options.template
            while not os.path.exists(tplfilename):
                tplfilename = commandLine.recieve('Default Template File', 'template.j2')
            deftemplate = Template(tplfilename)
        else:
            deftemplate = None
        # Read variables from CSV file, and generate device objects with each configs
        csvfilename = ''
        if options.inputcsv:
            csvfilename = options.inputcsv
        while not os.path.exists(csvfilename):
            csvfilename = commandLine.recieve('CSV File', 'data.csv')
        csvvars = get_vars_from_csv(csvfilename)
        ipvarid = 'ip'
        while ipvarid not in csvvars[0].keys():
            ipvarid = commandLine.recieve('Connection IP Var', 'ipaddress')
        for e in csvvars:
            devtemplate = deftemplate
            if 'template' in list(e.keys()):
                if e['template'] != 'default' and os.path.exists(e['template']):
                    devtemplate = Template(e['template'])
            if devtemplate != None:
                unsetvars = devtemplate.set_variables(e)
            (user, pswd) = commandLine.username, commandLine.password
            if 'username' in list(e.keys()):
                if e['username'] != 'default':
                    user = e['username']
            if 'password' in list(e.keys()):
                if e['password'] != 'default':
                    pswd = e['password']
            devconfig = 'NO CONFIG'
            if not options.getcommand:
                devconfig = devtemplate.render_template()
            manager.addDevice(e[ipvarid], user, pswd, config=devconfig)
        # Get Validation to Establish Device Connections and administer configurations
        if options.interactive:
            commandLine.establishUtility(manager)
            while commandLine.active:
                cmd = commandLine.utility()
        else:
            if not options.getcommand:
                if options.validate:
                    validations = int(options.validate)
                else:
                    validations = int(commandLine.recieve('Number of Validations', '2'))
                if validations > 0:
                    if options.ipaddress:
                        manager.devices[options.ipaddress].show()
                    else:
                        i=0
                        while i < validations:
                            manager.show(target='ip', ip=list(manager.devices.keys())[i])
                            i += 1
                    if not commandLine.acknowledge('Based on these configurations. Would you like to begin?'):
                        print('@@@ TERMINATING PROGRAM @@@\n')
                        sys.exit(-1)
            operate(manager, options)
    except KeyboardInterrupt:
        sys.exit(-1)
        pass

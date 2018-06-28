# DYNCONF V1.0: Dynamic Configuration
Config generator, administrator, and retriever based on Jinja2 templates, CSV data, and Netmiko SSH Sessions for Cisco IOS

2018 Dyntek Services Inc.
Kenneth J. Grace <kenneth.grace@dyntek.com>

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Warning:
	Not for use with non cisco-ios devices!

DEPEDENCIES:
	python3.6
	jinja2
	netmiko

Usage: dynconf.py [options]

Options:
  -h, --help            show this help message and exit
  -u USERNAME, --username=USERNAME
                        Default username for device connections
  -p PASSWORD, --password=PASSWORD
                        Default password for device connections
  -t TEMPLATE, --template=TEMPLATE
                        Read variables into a jinja2 template
  -c INPUTCSV, --csv=INPUTCSV
                        Read variables from a CSV file
  -v VALIDATE, --validate=VALIDATE
                        Number of config validations to perform
  -i IPADDRESS, --ipaddress=IPADDRESS
                        Single device to perform config on
  -w WRITETARGET, --writetarget=WRITETARGET
                        Write config on completion to keyed devices
  -s SHOWCMD, --show=SHOWCMD
                        Show output of target devices by key
  -G GETCOMMAND, --get=GETCOMMAND
                        Show command to send to machine
  -I, --interactive     Enable enhanced operation mode
  -Q, --quiet           Hide logging


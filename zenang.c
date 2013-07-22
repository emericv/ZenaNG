/**
 * ZenaNG Linux - a command line utility to interact with the Microchip
 * Technologies ZENA 2.5GHz 802.15.4 packet sniffer.
 * This tool support both bersion sniffer
 * * Old hardware based on CC2420 chip.
 * * Next gen hardware based on MRF24J40 chip 
 * 
 * Copyright (c) 2011,2012, Joe Desbonnet, jdesbonnet@gmail.com
 * Copyright (c) 2013, Emeric Verschuur, emericv@openihs.org
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <libusb-1.0/libusb.h>

#define APP_NAME "zena"
#define VERSION "0.5.0, 22 Jul 2013"
#define USB_VENDOR_ID 0x04d8   // Microchip Technologies Inc
#define INTERFACE 0

#define FORMAT_PCAP 1
#define FORMAT_USBHEX 2

#define TRUE 1
#define FALSE 0

#define ZENA_HW_PID 0x000e
#define ZENA_NG_HW_PID 0x0e00

#define HAS_FCS_FIELD 0x00000001

#define min(val1, val2) (val1 < val2 ? val1 : val2)

// Used by zena_get_packet() to return 802.15.4 packet data
typedef struct  {
	int zena_ts_sec;	// time stamp reported by ZENA (seconds)
	int zena_ts_usec;	// time stamp reported by ZENA (microseconds)
	int host_ts_sec;	// time stamp reported by host (seconds)
	int host_ts_usec;	// time stamp reported by host (microseconds)
	int packet_len;		// 802.15.4 packet len (excluding FCS)
	uint8_t packet[128];
	uint8_t rssi;
	uint8_t lqi;
	uint8_t fcs_ok;		// set to TRUE (1) if FCS ok, else FALSE (0)
} zena_packet_t;

typedef struct  {
	int product_id;
	int flags;
	int (*transfer) 
	(struct libusb_device_handle *dev_handle, unsigned char endpoint, 
						unsigned char *data, int length, int *transferred, 
						unsigned int timeout);
	int ep_packets;		// Packet endpoint
	int ep_control;		// Control endpoint
	int data_offset;
	int header_len;		// Zena header length
	int footer_len;		// Zena footer length
} zena_dev_profile_t;

const static zena_dev_profile_t dev_profile = {
	ZENA_HW_PID,
	0,
	libusb_interrupt_transfer,
	0x81,
	0x01,
	1,
	6,
	2
};

const static zena_dev_profile_t dev_profile_ng = {
	ZENA_NG_HW_PID,
	HAS_FCS_FIELD,
	libusb_bulk_transfer,
	0x82,
	0x01,
	2,
	7,
	4
};

static zena_dev_profile_t const *selected_profile;

const static int TIMEOUT=200; // Default USB timeout in ms
const static int PACKET_FRAG_TIMEOUT = 100; // USB timeout when retrieving 2nd or 3rd part of packet

// PCAP constants
const static int PCAP_MAGIC = 0xa1b2c3d4;
const static short PCAP_VERSION_MAJOR = 2;
const static short PCAP_VERSION_MINOR = 4;
const static int PCAP_TZ = 0;				// thiszone: GMT to local correction
const static int PCAP_SIGFIGS = 0;			// sigfigs: accuracy of timestamps
const static int PCAP_SNAPLEN = 128;		// snaplen: max len of packets, in octets
const static int PCAP_LINKTYPE = 0xc3;		// data link type DLT_IEEE802_15_4 (see <pcap/bpf.h>)


// Define error codes used internally
const static int ERR_INVALID_CHANNEL = -60 ;

// The debug level set with the -d command line switch
int debug_level = 0;

// Timeout used when reading packet data in milliseconds. Changed during
// packet scan to be the timeslice interval.
int usb_timeout = 200;

// Flag set to true if a kernel driver detach was performed. 
// Allows for reattach in exit handler.
int kernel_driver_detach = FALSE;

// Use -q flag to enable quiet mode. Warning messages will be suppressed.
int quiet_mode = FALSE;

// Use -x flag to write LQI and RSSI field.
int pcap_lqi_rssi_write = FALSE;

// Set to true in signal_handler to signal exit from main loop
int exit_flag = FALSE;

libusb_device *find_zena();
void debug (int level, const char *msg, ...);
void warning (const char *msg, ...);

/**
 * Locate and setup ZENA device on USB bus. Return libusb_device if successfully
 * found and setup. Return NULL if some error condition.
 *
 * @return libusb_device USB device handle for ZENA device or NULL if error condition.
 */
libusb_device_handle *setup_libusb_access() {

	int status;
	libusb_device_handle *zena = NULL;

	// libusb API 1.0 documentation here:
	// http://libusb.sourceforge.net/doc/function.usbsetconfiguration.html

	// Initialize libusb library. libusb_init() must be called before any 
	// other libusb_* function. If parameter is NULL use default libusb_context.
	// http://libusb.sourceforge.net/api-1.0/group__lib.html
	debug (1, "calling libusb_init() to initialize libusb");	
	status = libusb_init (NULL);
	if ( status < 0 ) {
		fprintf (stderr,"ERROR: Could not initialize libusb\n");
		return NULL;
	}

	// Set debugging level 0 .. 3. NULL param means use default usb context
	libusb_set_debug (NULL, (debug_level == 0 ? 0 : 3) );

	debug (1, "calling libusb_open_device_with_vid_pid() to open USB device handle to ZENA");
	selected_profile = &dev_profile; // Previous hardware
	zena = libusb_open_device_with_vid_pid (NULL, USB_VENDOR_ID, selected_profile->product_id);
	if (zena == NULL) { // Previous hardware not found
		selected_profile = &dev_profile_ng; // Next gen hardware
		zena = libusb_open_device_with_vid_pid (NULL, USB_VENDOR_ID, selected_profile->product_id);
	}
	if (zena == NULL) { // Next gen hardware not found
		fprintf (stderr,"ERROR: Could not open ZENA device. Not found or not accessible.\n");
		return NULL;
	}

	// Check if a kernel driver is attached to the device. Detach it if so.
	if (libusb_kernel_driver_active(zena,INTERFACE)) {
		warning("Kernel driver bound to ZENA. Attempting to detach.\n");
		debug(9,"calling libusb_detach_kernel_driver() to detach kernel driver from ZENA");
		status = libusb_detach_kernel_driver(zena,INTERFACE);
		if ( status < 0 ) {
			fprintf (stderr,"ERROR: could not detach kernel driver from ZENA, errorCode=%d",status);
			return NULL;
		}
		kernel_driver_detach = TRUE;
		debug (9,"kernel driver detach successful.\n");
	}
	
	// From "lsusb -v" bConfigurationValue is 1.
	// TODO: what does this mean?
	debug (9, "calling usb_set_configuration()");
	status = libusb_set_configuration(zena, 1);
	if ( status < 0 ) {
		fprintf(stderr,"ERROR: Could not set configuration 1: errorCode=%d\n", status);
		return NULL;
	}
 
	// Claim interface. This is problematic. When ZENA is first plugged in
	// something in the OS automatically 'binds' it causing this to fail.
	// Can we programatically 'unbind' it? Maybe with usb_release_interface()?
	debug (1, "calling libusb_claim_interface(%d)",INTERFACE);
	status = libusb_claim_interface(zena, INTERFACE);
	if ( status < 0) {
		fprintf(stderr,"ERROR: Could not claim interface %d: errorCode=%d. Is device already bound?\n",INTERFACE,status);
		return NULL;
	}
 
	// Success, return usb_dev_handle
	debug (1,"ZENA successfully located and claimed");
	return zena;
}
 

/**
 * Select 802.15.4 channel on ZENA. 
 * 
 * Empty packet buffers before changing channel (otherwise
 * it won't be clear from which channel a packet arrived).
 *
 * @param zena The libusb_device_handle of ZENA device
 * @param channel The 802.15.4 channel. Must be 11 to 26.
 *
 * @return int Return 0 if successful or error code < 0 if error condition.
 * ERR_INVALID_CHANNEL: channel out of allowed range. Must be >= 11 and <= 26.
 */
int zena_set_channel (libusb_device_handle *zena, int channel) {

	debug (1,"zena_set_channel(), 802.15.4 channel = %d", channel);

	// Check if valid channel
	if (channel < 11 || channel > 26) {
		return ERR_INVALID_CHANNEL;
	}

	// Require a 64 byte buffer to send USB packet to ZENA
	unsigned char usbbuf[64];

	// Number of bytes actually transferred stored here. Not used.
	int status,nbytes;

	// set buffer to all zero
	bzero (usbbuf,64);		

	// Channel is byte offset 1 in packet
	usbbuf[1] = channel;

	// Send to device selected_profile->ep_control end point.
	// http://libusb.sourceforge.net/api-1.0/group__syncio.html
	debug (1, "calling libusb_transfer() to selected_profile->ep_control");
	status = selected_profile->transfer (zena, selected_profile->ep_control, usbbuf, 64, &nbytes, TIMEOUT);
	if ( status < 0 ) {
		fprintf (stderr,"ERROR: zena_set_channel(): error on libusb_transfer(). errorCode=%d\n", status);
		return status;
	}

	debug (1, "ZENA is now set to 802.15.4 channel %d", channel);

	// Flush packet buffers by reading. We need to do this because packet
	// may have arrived before channel was changed. We we allow such packets
	// to be outputted it will be tagged with the incorrect 802.15.4 channel.
	// Better to loose this data than have inaccurate data.
	do {
		status = selected_profile->transfer (zena, selected_profile->ep_packets, usbbuf, 64, &nbytes, PACKET_FRAG_TIMEOUT);
		if (nbytes>0) {
			debug (9,"found %d bytes in buffer after channel change\n", nbytes);
		}
	} while (nbytes>0);


}



/**
 * Retrieve one 802.15.4 packet from ZENA. This may require multiple 64 byte
 * USB read requests.
 *
 * @param zena libusb_device_handle for ZENA USB device which must be open and ready
 * @param zena_packet A memory structure which will be populated with 802.15.4 packet
 * data and metadata read from the ZENA
 * 
 * @return 0 on success. Negative error code on failure. If an error code is returned
 * the contents of zena_packet is undefined.
 * TODO: mixing up libusb return codes with my own return codes.
 */
int zena_get_packet (libusb_device_handle *zena,  zena_packet_t *zena_packet) {

	int status,nbytes,data_len,packet_len;
	struct timespec tp;
	uint8_t usbbuf[64];

	// http://libusb.sourceforge.net/doc/function.usbinterruptread.html
	// Documentation says status should contain the number of bytes read.
	// This is not what I'm finding. Getting 0 on success.
	//debug (1, "calling usb_interrupt_read()");
	status = selected_profile->transfer(zena, selected_profile->ep_packets, usbbuf, 64, &nbytes, usb_timeout);
	// check for timeout and silently ignore
	if (status == LIBUSB_ERROR_TIMEOUT) {
		debug(9,"zena_get_packet(): libusb_transfer() timeout");
		return status;
	}

	// a real error (ie not timeout)
	// LIBUSB_ERROR_IO = -1
	if (status < 0) {
		fprintf (stderr,"ERROR: error retrieving ZENA packet, errorCode=%d\n", status);
		return -2;
	}

	// get host time of packet reception
	clock_gettime(CLOCK_REALTIME, &tp);

	// Get packet timestamp from ZENA header + capture start time
	zena_packet->host_ts_sec = tp.tv_sec;
	zena_packet->host_ts_usec = tp.tv_nsec / 1000;

	zena_packet->zena_ts_sec = (int)usbbuf[selected_profile->data_offset + 2]
			| ( ((int)usbbuf[selected_profile->data_offset + 3])<<8 );
	zena_packet->zena_ts_usec = ( ((int)usbbuf[selected_profile->data_offset])
			| ( ((int)usbbuf[selected_profile->data_offset + 1])<<8 )) * 15; //approx
	
	data_len = usbbuf[selected_profile->header_len - 1];

	// Check for invalid packet lengths
	if (data_len > 129) {
		warning("Packet too long, length=%d. Ignoring.\n",data_len);
		return -3;
	}
	
	int bytesRemaining = data_len;
	int fragMaxLen = 64 - selected_profile->header_len;
	int nb_read = min(bytesRemaining, fragMaxLen);
	memcpy (zena_packet->packet, usbbuf + selected_profile->header_len, nb_read);
	bytesRemaining -= nb_read;
	
	if (bytesRemaining > 0) {
		int write_offset = nb_read;
		fragMaxLen = 64 - selected_profile->data_offset;
		while (bytesRemaining > 0) {
			status = selected_profile->transfer(zena, selected_profile->ep_packets, usbbuf, 64, &nbytes, PACKET_FRAG_TIMEOUT);

			// A status < 0 here will be problematic. Likely that the data will be corrupted. But
			// as the packet header is already written, might as well write what's in the buffer 
			// and display a warning message.
			if (status < 0) {
				warning ("libusb_transfer() returned status=%d during second chunk of long packet\n", status);
				return status;
			}
			
			nb_read = min(bytesRemaining, fragMaxLen);
			memcpy (zena_packet->packet + write_offset, usbbuf + selected_profile->data_offset, nb_read);
			bytesRemaining -= nb_read;
			write_offset += nb_read;
		}
	}

	if (selected_profile->product_id == ZENA_HW_PID) { // hold HW
		zena_packet->rssi = zena_packet->packet[data_len-2];
		zena_packet->lqi = zena_packet->packet[data_len-1]&0x7f;
		zena_packet->fcs_ok = zena_packet->packet[data_len-1]&80 ? TRUE : FALSE;
		zena_packet->packet_len = data_len - 2;
	} else { // Next gen HW
		zena_packet->rssi = zena_packet->packet[data_len-1];
		zena_packet->lqi = zena_packet->packet[data_len-2];
		zena_packet->fcs_ok = TRUE; // TODO: compute it from bytes data_len-4 and data_len-3
		zena_packet->packet_len = data_len - 2;
	}

	return 0;
}

/**
 * Display help and usage information. 
 */
void usage () {
	fprintf (stderr,"\n");
	fprintf (stderr,"Usage: zena -c channel [-f format] [-b] [-q] [-v] [-h] [-d level]\n");
	fprintf (stderr,"  -c channel \t Select 802.15.4 channel. Allowed: 11 .. 26\n");
	fprintf (stderr,"  -f format \t Select packet capture format. Allowed: pcap (default) or usbhex.\n");
	fprintf (stderr,"  -d level \t Set debug level, 0 = min [default], 9 = max verbosity\n");
	fprintf (stderr,"  -s interval \t Scan through 802.15.4 channels with timeslice interval in milliseconds\n");
	fprintf (stderr,"  -x \t Write the both LQI and RSSI bytes (applicable to the PCAP format)\n");
	fprintf (stderr,"  -b \t Include corrupted packets. Applies to pcap output only.\n");
	fprintf (stderr,"  -q \t Quiet mode: suppress warning messages.\n");
	fprintf (stderr,"  -v \t Print version to stderr and exit\n");
	fprintf (stderr,"  -h \t Display this message to stderr and exit\n");

	fprintf (stderr,"\n");
	fprintf (stderr,"Packet capture output is sent to standard output. Use the following command to\n");
	fprintf (stderr,"display real time packet feed in wireshark:\n  wireshark -k -i <( zena -c 20 )\n");

	fprintf (stderr,"\n");
	fprintf (stderr,"Project code and documentation is hosted at:\n  http://code.google.com/p/microchip-zena/\n");
	fprintf (stderr,"\n");
}

void version () {
	fprintf (stderr,"%s, version %s\n", APP_NAME, VERSION);
}

/**
 * Display debug message if suitable log level is selected. 
 * Use vararg mechanism to allow use similar to the fprintf()
 * function.
 *
 * @param level Display this message if log level is greater
 * or equal this level. Otherwise ignore the message.
 * @param msg  Format string as described in fprintf()
 */
void debug (int level, const char* msg, ...) {
	if (level >= debug_level) {
		return;
	}
	va_list args;
	va_start(args, msg);		// args after 'msg' are unknown
	vfprintf(stderr, msg, args);
	fprintf(stderr,"\n");
	fflush(stderr);
	va_end(args);
}
/**
 * Display warning message if unless quiet_mode is enabled.
 * 
 * @param msg  Format string as described in fprintf()
 */
void warning (const char* msg, ...) {
	if (quiet_mode) {
		return;
	}
	fprintf(stderr,"WARNING: ");
	va_list args;
	va_start(args, msg);		// args after 'msg' are unknown
	vfprintf(stderr, msg, args);
	fprintf(stderr,"\n");
	fflush(stderr);
	va_end(args);
}

/**
 * Signal handler for handling SIGPIPE and...
 */
void signal_handler(int signum, siginfo_t *info, void *ptr) {
	debug (1, "Received signal %d originating from PID %lu\n", signum, (unsigned long)info->si_pid);
	//exit(EXIT_SUCCESS);
	exit_flag = TRUE;
}


int main( int argc, char **argv) {

	libusb_device_handle *zena;

	int channel = -1;			// no default 802.15.4 channel
	int format = FORMAT_PCAP;	// PCAP is default output format
	int scan_mode = FALSE;
	int drop_bad_packets = TRUE;
	int exit_time = -1;

	int c;

	// Setup signal handler. Catching SIGPIPE allows for exit when 
	// piping to Wireshark for live packet feed.
	//signal(SIGPIPE, signal_handler);
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = signal_handler;
	act.sa_flags = SA_SIGINFO;
	sigaction(SIGPIPE, &act, NULL);


	// Parse command line arguments. See usage() for details.
	while ((c = getopt(argc, argv, "bc:d:f:hqs:t:vx")) != -1) {
		switch(c) {
			case 'b':
				drop_bad_packets = FALSE;
				break;
			case 'c':
				channel = atoi (optarg);
				if (channel < 11 || channel > 26) {
					fprintf (stderr, "ERROR: Invalid channel. Must be in rage 11 to 26. Use -h for help.\n");
					exit(-1);
				}
				break;
			case 'd':
				debug_level = atoi (optarg);
				break;
			case 'f':
				if (strcmp(optarg,"pcap")==0) {
					format = FORMAT_PCAP;
				} else if (strcmp(optarg,"usbhex")==0) {
					format = FORMAT_USBHEX;
				} else {
					fprintf(stderr,"ERROR: unrecognized output format '%s'. Only pcap or usbhex allowed.\n",optarg);
					exit(-1);
				}
            	break;
			case 'h':
				version();
				usage();
				exit(EXIT_SUCCESS);
			case 'q':
				quiet_mode = TRUE;
				break;
			case 's':
				scan_mode = TRUE;
				usb_timeout = atoi (optarg);
				break;
			case 't':
				exit_time = atoi(optarg);
				break;
			case 'v':
				version();
				exit(EXIT_SUCCESS);
			case 'x':
				pcap_lqi_rssi_write = TRUE;
				break;
			case '?':	// case when a command line switch argument is missing
				if (optopt == 'c') {
					fprintf (stderr,"ERROR: 802.15.4 channel 11 to 26 must be specified with -c\n");
					exit(-1);
				}
				if (optopt == 'd') {
					fprintf (stderr,"ERROR: debug level 0 .. 9 must be specified with -d\n");
					exit(-1);
				}
				if (optopt == 'f') {
					fprintf (stderr,"ERROR: pcap or usbhex format must be specified with -f\n");
					exit(-1);
				}
				break;
		}
	}

	if (channel == -1) {
		fprintf (stderr,"ERROR: 802.15.4 channel is mandatory. Specify with -c. Use -h for help.\n");
		exit(EXIT_FAILURE);
	}

	if (debug_level > 0) {
		fprintf (stderr,"DEBUG: debug level %d\n",debug_level);
	}

	// Locate ZENA on the USB bus and get handle.
	if ((zena = setup_libusb_access()) == NULL) {
		fprintf (stderr, "ERROR: ZENA device not found or not accessible\n");
		exit(EXIT_FAILURE);
	}

	// Set 802.15.4 channel
	int status = zena_set_channel (zena,channel);
	if (status < 0) {
		fprintf (stderr, "ERROR: error setting ZENA to 802.15.4 channel %d, errorCode=%d\n",channel,status);
		exit(EXIT_FAILURE);
	} 

	// Write PCAP header
	if (format == FORMAT_PCAP) {
		fwrite(&PCAP_MAGIC, sizeof(int), 1, stdout);    
		fwrite(&PCAP_VERSION_MAJOR, sizeof(short), 1, stdout);
		fwrite(&PCAP_VERSION_MINOR, sizeof(short), 1, stdout);
		fwrite(&PCAP_TZ, sizeof(int), 1, stdout);				// thiszone: GMT to local correction
		fwrite(&PCAP_SIGFIGS, sizeof(int), 1, stdout);			// sigfigs: accuracy of timestamps
		fwrite(&PCAP_SNAPLEN, sizeof(int), 1, stdout);			// snaplen: max len of packets, in octets
		fwrite(&PCAP_LINKTYPE, sizeof(int), 1, stdout);		// data link type
	}

	int i,j,data_len,packet_len,packet_len_plus_2,ts_sec,ts_usec;

	// Allocate buffer for usb_interrupt_read requests
	unsigned char usbbuf[64];
	//unsigned char packetbuf[128];
	
	// Get start time of capture. Won't worry about subsecond resolution for this.
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME, &tp);
	int start_sec = tp.tv_sec;

	// Store the number of bytes actually transferred here
	int nbytes;

	// Packet counter
	int npacket=0;

	zena_packet_t zena_packet;

	// Main loop
	while ( ! exit_flag ) {

		// If scan_mode is TRUE, cycle through all the 802.15.4 channels looking
		// for packets. For some reason it seems to be necessary to close the 
		// USB device and libusb library and reopen it for the channel change to 
		// work reliably. Why?

		if (scan_mode) {

			channel++;
			if (channel > 26) {
				channel = 11;
			}

			// It seems to be necessary to reset libusb (close library and 
			// re-initialize it) for zena_set_channel() to be successful.
			debug(9,"Closing ZENA to facilitate 802.15.4 channel change");
			libusb_close (zena);
			debug(9,"Closing libusb library to facilitate 802.15.4 channel change");
			libusb_exit(NULL);
			debug(9,"Reopening ZENA");
		        if ((zena = setup_libusb_access()) == NULL) {
				fprintf (stderr, "ERROR: unable to reopen ZENA during 80.15.4 channel change\n");
				exit(EXIT_FAILURE);
			}
	
			debug (1,"Setting 802.15.4 channel to %d",channel);
			status = zena_set_channel(zena,channel);
			if (status<0) {
				fprintf (stderr,"ERROR: error setting 802.15.4 channel to %d during scan, errorCode=%d\n",channel, status);
				exit(EXIT_FAILURE);
			} 

			// TODO: bug - we can have packet received from the
			// previous 802.15.4 channel in the buffer at this
			// point. When outputted it will be incorrectly
			// tagged with the new channel number. Can we purge
			// the buffer somehow?
			
		}

		switch (format) {

			case FORMAT_USBHEX:

				status = selected_profile->transfer(zena, selected_profile->ep_packets, usbbuf, 64, &nbytes, usb_timeout);
				// check for timeout and silently ignore
				if (status == LIBUSB_ERROR_TIMEOUT) {
					debug(9,"libusb_transfer(): timeout");
					continue;
				}

				// get host time of packet reception
				clock_gettime(CLOCK_REALTIME, &tp);
				if ( (exit_time>0) && (tp.tv_sec > (start_sec + exit_time))) {
					debug(1,"Exit time reached. Exiting.");
					exit(EXIT_SUCCESS);
				}

				// a real error (ie not timeout)
				if (status < 0) {
					fprintf (stderr,"ERROR: error retrieving ZENA packet, errorCode=%d\n", status);
					continue;
				}

				// Packet timestamp
				fprintf (stdout,"%ld.%ld ",tp.tv_sec,tp.tv_nsec);

				// 802.15.4 channel
				fprintf (stdout, "%02x ", channel);

				// Echo USB 64 byte packet to screen. Each byte as hex separated by space. 
				// One line per packet.
				for (j = 0; j < 64; j++) {
					fprintf (stdout, "%02x ", usbbuf[j] & 0xff);
				}
				fprintf (stdout, "\n");
				fflush (stdout);
				break;

			case FORMAT_PCAP:
				status = zena_get_packet (zena, &zena_packet);
				if (status == LIBUSB_ERROR_TIMEOUT) {
					// A timeout is a normal event. No action.
					break;
				}
				if (status != 0) {
					fprintf (stderr,"ERROR: retrieving packet, errorCode=%d\n",status);
					break;
				}

				// Ensure that zena_packet.packet_len is a sane value. Occasionally getting crazy
				// values which causes segv when accessing the zena_packet.packet[] buffer.
				zena_packet.packet_len &= 0xff;
				if (zena_packet.packet_len > 125) {
					fprintf (stderr,"ERROR: invalid packet length, len=%d\n",zena_packet.packet_len);
					break;
				}

				if (  ( ! zena_packet.fcs_ok) && drop_bad_packets ) {
					warning ("dropping corrupted packet\n");
					break;
				}

				npacket++;

				// Write PCAP packet header
				fwrite (&zena_packet.host_ts_sec, sizeof(int), 1, stdout);	// ts_sec: timestamp seconds
				fwrite (&zena_packet.host_ts_usec, sizeof(int), 1, stdout);	// ts_usec: timestamp microseconds

				if (selected_profile->flags & HAS_FCS_FIELD) {
					fwrite (&zena_packet.packet_len, sizeof(int), 1, stdout);
					fwrite (&zena_packet.packet_len, sizeof(int), 1, stdout);
					fwrite (zena_packet.packet, 1, zena_packet.packet_len, stdout);
				} else if (pcap_lqi_rssi_write) {
					packet_len_plus_2 = zena_packet.packet_len + 2;
					fwrite (&packet_len_plus_2, sizeof(int), 1, stdout);
					fwrite (&packet_len_plus_2, sizeof(int), 1, stdout);
					fwrite (zena_packet.packet, 1, zena_packet.packet_len, stdout);
				} else
					
				// Small problem re FCS. Old HW ZENA does not provide this information.
				// Solution is in the case of a good packet not to include FCS
				// and Wireshark will ignore it. In the case were the FCS is 
				// known to be bad, we'll include a deliberatly wrong FCS. For
				// the moment this will be a fixed value (0x0000), but ideally
				// it should be computed from the packet and the +1 to guarantee
				// it is a bad FCS.
					
					if (zena_packet.fcs_ok) {
					packet_len_plus_2 = zena_packet.packet_len + 2;
					
					// write packet excluding FCS
					fwrite (&zena_packet.packet_len, sizeof(int), 1, stdout);
					fwrite (&packet_len_plus_2, sizeof(int), 1, stdout);	// full frame included 2 FCS octets
					fwrite (zena_packet.packet, 1, zena_packet.packet_len, stdout);
				} else {
					packet_len_plus_2 = zena_packet.packet_len + 2;
					
					// two extra bytes for deliberately wrong FCS
					fwrite (&packet_len_plus_2, sizeof(int), 1, stdout);
					fwrite (&packet_len_plus_2, sizeof(int), 1, stdout);
					zena_packet.packet[zena_packet.packet_len] = 0;
					zena_packet.packet[zena_packet.packet_len+1] = 0;
					fwrite (zena_packet.packet, 1, packet_len_plus_2, stdout);
				}

				fflush(stdout);
				break;


		} // end switch


	} // end main loop

	// Release USB interface and close USB connection.
	// This code never reached at the moment -- need to implement signal handler for this.
	// However I've noticed no resource leaks. Process kill seems to take care of this.
	libusb_close (zena);
	libusb_exit(NULL);

	debug (1, "Normal exit");
	return EXIT_SUCCESS; 
}

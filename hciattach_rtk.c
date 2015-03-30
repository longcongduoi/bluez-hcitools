/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2013-2014  Realtek Semiconductor Corp.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"

#include "hciattach.h"

static int bt_debug = 1;

#define BT_DBG(fmt, ...) \
do { \
	if (bt_debug) \
		fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
} while (0)

#define BT_ERR(fmt, ...) \
do { \
	fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
} while (0)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(d)  (d)
#define cpu_to_le32(d)  (d)
#define le16_to_cpu(d)  (d)
#define le32_to_cpu(d)  (d)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le16(d)  bswap_16(d)
#define cpu_to_le32(d)  bswap_32(d)
#define le16_to_cpu(d)  bswap_16(d)
#define le32_to_cpu(d)  bswap_32(d)
#else
#error "Unknown byte order"
#endif

#define HCI_VENDOR_READ_ROM_VERSION	0xfc6d
#define HCI_VENDOR_READ_LMP_VERSION	0x1001

typedef struct {
        uint8_t status;
        uint8_t version;
} __attribute__ ((packed)) read_rom_version_rp;
#define READ_ROM_VERSION_RP_SIZE 2

#define RTK_ROM_LMP_3499	0x3499
#define RTK_ROM_LMP_8723A	0x1200
#define RTK_ROM_LMP_8723B	0x8723
#define RTK_ROM_LMP_8723B2	0x4ce1
#define RTK_ROM_LMP_8821A	0x8821
#define RTK_ROM_LMP_8761A	0x8761

static const uint8_t RTK_EPATCH_SIGNATURE[8] = {
	0x52, 0x65, 0x61, 0x6C, 0x74, 0x65, 0x63, 0x68
};

#define RTK_FRAG_LEN 252

typedef struct {
	uint8_t index;
	uint8_t data[RTK_FRAG_LEN];
} __attribute__ ((packed)) rtk_download_request;

typedef struct {
        uint8_t status;
        uint8_t index;
} __attribute__ ((packed)) rtk_download_response;

typedef struct {
	uint8_t signature[8];
	uint32_t fw_version;
	uint16_t num_patches;
} __attribute__ ((packed)) rtk_epatch_header;

#ifndef FIRMWARE_DIR
#define FIRMWARE_DIR "/lib/firmware/"
#endif

struct hci_uart {
	int tty_fd;
	struct termios *ti;
	char *bdaddr;

	void *priv;

	unsigned char cmd_buf[1024];
	unsigned int cmd_len;
	enum {
	        cmd_not_send,
	        cmd_has_sent,
	        event_received,
	} cmd_state;
	unsigned int cmd_timeout;
	unsigned int cmd_timeout_count;

	uint16_t lmp_subver;
	uint8_t rom_version;
};

static struct hci_uart *hu;

#define HCI_3WIRE_ACK_PKT	0
#define HCI_3WIRE_LINK_PKT	15

/*
 * Maximum Three-wire packet:
 *     4 byte header + max value for 12-bit length + 2 bytes for CRC
 */
#define H5_MAX_LEN (4 + 0xfff + 2)

/* Convenience macros for reading Three-wire header values */
#define H5_HDR_SEQ(hdr)		((hdr)[0] & 0x07)
#define H5_HDR_ACK(hdr)		(((hdr)[0] >> 3) & 0x07)
#define H5_HDR_CRC(hdr)		(((hdr)[0] >> 6) & 0x01)
#define H5_HDR_RELIABLE(hdr)	(((hdr)[0] >> 7) & 0x01)
#define H5_HDR_PKT_TYPE(hdr)	((hdr)[1] & 0x0f)
#define H5_HDR_LEN(hdr)		((((hdr)[1] >> 4) & 0xff) + ((hdr)[2] << 4))

#define SLIP_DELIMITER	0xc0
#define SLIP_ESC	0xdb
#define SLIP_ESC_DELIM	0xdc
#define SLIP_ESC_ESC	0xdd

struct h5 {
	enum {
		H5_RX_NOESC,
		H5_RX_ESC,
	} esc_state;

	struct sk_buff *rx_skb;
	size_t rx_pending;
	uint8_t rx_ack;

	int (*rx_func)(struct hci_uart *hu, unsigned char c);

	uint8_t tx_seq;
	uint8_t tx_ack;

	enum {
		H5_SYNC,
		H5_CONFIG,
		H5_INIT,
		H5_PATCH,
		H5_ACTIVE,
	} state;
};

struct sk_buff {
	unsigned int max_len;
	unsigned int data_len;
	unsigned char data[0];
};

static __inline struct sk_buff *skb_alloc(unsigned int len)
{
	struct sk_buff *skb = NULL;

	skb = malloc(len + 8);
	if (skb) {
		skb->max_len = len;
		skb->data_len = 0;
		memset(skb->data, 0, len);
	}

	return skb;
}

static __inline void free_skb(struct sk_buff *skb)
{
	free(skb);
}

static unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned int old_len = skb->data_len;

	if ((skb->data_len + len) > (skb->max_len))
		return NULL;

	skb->data_len += len;

	return (skb->data + old_len);
}

static unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
{
	unsigned char *buf;

	buf = malloc(skb->data_len);
	if (!buf)
		exit(1);

	skb->data_len -= len;

	memcpy(buf, skb->data + len, skb->data_len);
	memcpy(skb->data, buf, skb->data_len);
	free(buf);

	return skb->data;
}

static struct sk_buff *h5_prepare_pkt(struct hci_uart *hu, uint8_t pkt_type,
		const uint8_t *data, size_t len);

static void h5_cmd_send(struct hci_uart *hu, const void *data, size_t len)
{
	struct sk_buff *nskb;

	nskb = h5_prepare_pkt(hu, HCI_COMMAND_PKT, data, len);

	write(hu->tty_fd, nskb->data, nskb->data_len);

	free_skb(nskb);
}

static void h5_ack_send(struct hci_uart *hu, const void *data, size_t len)
{
	struct sk_buff *nskb;

	nskb = h5_prepare_pkt(hu, HCI_3WIRE_ACK_PKT, NULL, 0);

	write(hu->tty_fd, nskb->data, nskb->data_len);

	free_skb(nskb);
}

static void h5_reset_rx(struct h5 *h5);

static void h5_link_control(struct hci_uart *hu, const void *data, size_t len)
{
	struct sk_buff *nskb;

	nskb = h5_prepare_pkt(hu, HCI_3WIRE_LINK_PKT, data, len);

	write(hu->tty_fd, nskb->data, nskb->data_len);

	free_skb(nskb);
}

static void h5_timed_event(struct hci_uart *hu, struct sk_buff *skb)
{
	evt_cmd_complete *compl;
	uint16_t opcode = 0;

	skb_pull(skb, HCI_EVENT_HDR_SIZE);

	compl = (evt_cmd_complete *)skb->data;
	opcode = le16_to_cpu(compl->opcode);

	skb_pull(skb, EVT_CMD_COMPLETE_SIZE);

	switch (opcode) {
	case HCI_VENDOR_READ_LMP_VERSION:
		hu->cmd_state = event_received;
		memcpy(hu->cmd_buf, skb->data, skb->data_len);
		break;

	case HCI_VENDOR_READ_ROM_VERSION:
		hu->cmd_state = event_received;
		memcpy(hu->cmd_buf, skb->data, skb->data_len);
		break;

	case 0xfc20:
		hu->cmd_state = event_received;
		memcpy(hu->cmd_buf, skb->data, skb->data_len);
		break;
	}
}

static void h5_handle_internal_rx(struct hci_uart *hu)
{
	struct h5 *h5 = hu->priv;
	const unsigned char sync_req[] = { 0x01, 0x7e };
	const unsigned char sync_rsp[] = { 0x02, 0x7d };
	const unsigned char conf_req[] = { 0x03, 0xfc, 0x01 };
	const unsigned char conf_rsp[] = { 0x04, 0x7b };
	const unsigned char *data = h5->rx_skb->data;

	if (h5->state == H5_SYNC) {
		if (memcmp(data, sync_req, 2) == 0)
			h5_link_control(hu, sync_rsp, sizeof(sync_rsp));
		else if (memcmp(data, sync_rsp, 2) == 0)
			h5->state = H5_CONFIG;
	} else if (h5->state == H5_CONFIG) {
		if (memcmp(data, sync_req, 2) == 0)
			h5_link_control(hu, sync_rsp, sizeof(sync_rsp));
		else if (memcmp(data, conf_req, 2) == 0)
			h5_link_control(hu, conf_rsp, sizeof(conf_rsp));
		else if (memcmp(data, conf_rsp, 2) == 0)
			h5->state = H5_INIT;
		else
			h5_ack_send(hu, NULL, 0);
	} else if (h5->state == H5_INIT) {
		if (data[0] == 0x0e)
			h5_timed_event(hu, h5->rx_skb);

		h5_ack_send(hu, NULL, 0);
	} else if (h5->state == H5_PATCH) {
		h5_timed_event(hu, h5->rx_skb);
	} else {
		BT_DBG("Link Control: 0x%02hhx 0x%02hhx", data[0], data[1]);
		return;
	}
}

static void h5_complete_rx_pkt(struct hci_uart *hu)
{
	struct h5 *h5 = hu->priv;
	const unsigned char *hdr = h5->rx_skb->data;

	if (H5_HDR_RELIABLE(hdr))
		h5->tx_ack = (h5->tx_ack + 1) % 8;

	h5->rx_ack = H5_HDR_ACK(hdr);

	switch (H5_HDR_PKT_TYPE(hdr)) {
	case HCI_EVENT_PKT:
	case HCI_ACLDATA_PKT:
	case HCI_SCODATA_PKT:
	case HCI_COMMAND_PKT:
	case HCI_3WIRE_LINK_PKT:
		skb_pull(h5->rx_skb, 4);
		h5_handle_internal_rx(hu);
		break;

	default:
		break;
	}

	h5_reset_rx(h5);
}

static int h5_rx_crc(struct hci_uart *hu, unsigned char c)
{
	h5_complete_rx_pkt(hu);

	return 0;
}

static int h5_rx_payload(struct hci_uart *hu, unsigned char c)
{
	struct h5 *h5 = hu->priv;
	const unsigned char *hdr = h5->rx_skb->data;

	if (H5_HDR_CRC(hdr)) {
		h5->rx_func = h5_rx_crc;
		h5->rx_pending = 2;
	} else {
		h5_complete_rx_pkt(hu);
	}

	return 0;
}

static int h5_rx_3wire_hdr(struct hci_uart *hu, unsigned char c)
{
	struct h5 *h5 = hu->priv;
	const unsigned char *hdr = h5->rx_skb->data;

	if (((hdr[0] + hdr[1] + hdr[2] + hdr[3]) & 0xff) != 0xff) {
		BT_ERR("Invalid header checksum");
		h5_reset_rx(h5);
		return 0;
	}

	if (H5_HDR_RELIABLE(hdr) && H5_HDR_SEQ(hdr) != h5->tx_ack) {
		BT_ERR("Out-of-order packet arrived (%u != %u)",
		       H5_HDR_SEQ(hdr), h5->tx_ack);
		h5_reset_rx(h5);
		return 0;
	}

	h5->rx_func = h5_rx_payload;
	h5->rx_pending = H5_HDR_LEN(hdr);

	return 0;
}

static int h5_rx_pkt_start(struct hci_uart *hu, unsigned char c)
{
	struct h5 *h5 = hu->priv;

	if (c == SLIP_DELIMITER)
		return 1;

	h5->rx_func = h5_rx_3wire_hdr;
	h5->rx_pending = 4;
	h5->esc_state = H5_RX_NOESC;

	h5->rx_skb = skb_alloc(H5_MAX_LEN);
	if (!h5->rx_skb) {
		BT_ERR("Can't allocate mem for new packet");
		h5_reset_rx(h5);
		return 0;
	}

	return 0;
}

static int h5_rx_delimiter(struct hci_uart *hu, unsigned char c)
{
	struct h5 *h5 = hu->priv;

	if (c == SLIP_DELIMITER)
		h5->rx_func = h5_rx_pkt_start;

	return 1;
}

static void h5_unslip_one_byte(struct h5 *h5, unsigned char c)
{
	const uint8_t delim = SLIP_DELIMITER, esc = SLIP_ESC;
	const uint8_t oof1 = 0x11, oof2 = 0x13;
	const uint8_t *byte = &c;

	if (h5->esc_state == H5_RX_NOESC && c == SLIP_ESC) {
		h5->esc_state = H5_RX_ESC;
		return;
	}

	if (h5->esc_state == H5_RX_ESC) {
		switch (c) {
		case SLIP_ESC_DELIM:
			byte = &delim;
			break;
		case SLIP_ESC_ESC:
			byte = &esc;
			break;
		case 0xde:
			byte = &oof1;
			break;
		case 0xdf:
			byte = &oof2;
			break;
		default:
			BT_ERR("Invalid esc byte 0x%02hhx", c);
			h5_reset_rx(h5);
			return;
		}
	}

	memcpy(skb_put(h5->rx_skb, 1), byte, 1);
	h5->esc_state = H5_RX_NOESC;
	h5->rx_pending--;

	BT_DBG("unsliped 0x%02hhx, rx_pending %zu", *byte, h5->rx_pending);
}

static void h5_reset_rx(struct h5 *h5)
{
	if (h5->rx_skb) {
		free_skb(h5->rx_skb);
		h5->rx_skb = NULL;
	}

	h5->rx_func = h5_rx_delimiter;
	h5->rx_pending = 0;
	h5->esc_state = H5_RX_NOESC;
}

static int h5_recv(struct hci_uart *hu, void *data, int count)
{
	struct h5 *h5 = hu->priv;
	unsigned char *ptr = data;

	BT_DBG("pending %zu count %d", h5->rx_pending, count);

	while (count > 0) {
		int processed;

		if (h5->rx_pending > 0) {
			if (*ptr == SLIP_DELIMITER) {
				BT_ERR("Too short H5 packet");
				h5_reset_rx(h5);
				continue;
			}

			h5_unslip_one_byte(h5, *ptr);

			ptr++; count--;
			continue;
		}

		processed = h5->rx_func(hu, *ptr);
		if (processed < 0)
			return processed;

		ptr += processed;
		count -= processed;
	}

	return count;
}

static void h5_slip_delim(struct sk_buff *skb)
{
	const char delim = SLIP_DELIMITER;

	memcpy(skb_put(skb, 1), &delim, 1);
}

static void h5_slip_one_byte(struct sk_buff *skb, unsigned char c)
{
	const unsigned char esc_delim[2] = { SLIP_ESC, SLIP_ESC_DELIM };
	const unsigned char esc_esc[2] = { SLIP_ESC, SLIP_ESC_ESC };
	const unsigned char esc_11[2] = { SLIP_ESC, 0xde };
	const unsigned char esc_13[2] = { SLIP_ESC, 0xdf };

	switch (c) {
	case SLIP_DELIMITER:
		memcpy(skb_put(skb, 2), &esc_delim, 2);
		break;
	case SLIP_ESC:
		memcpy(skb_put(skb, 2), &esc_esc, 2);
		break;
	case 0x11:
		memcpy(skb_put(skb, 2), &esc_11, 2);
		break;
	case 0x13:
		memcpy(skb_put(skb, 2), &esc_13, 2);
		break;
	default:
		memcpy(skb_put(skb, 1), &c, 1);
	}
}

static int valid_packet_type(uint8_t type)
{
	switch (type) {
	case HCI_ACLDATA_PKT:
	case HCI_COMMAND_PKT:
	case HCI_SCODATA_PKT:
	case HCI_3WIRE_LINK_PKT:
	case HCI_3WIRE_ACK_PKT:
		return 1;
	default:
		return 0;
	}
}

static struct sk_buff *h5_prepare_pkt(struct hci_uart *hu, uint8_t pkt_type,
		const uint8_t *data, size_t len)
{
	struct h5 *h5 = hu->priv;
	struct sk_buff *nskb;
	uint8_t hdr[4];
	int i;

	if (!valid_packet_type(pkt_type)) {
		BT_ERR("Unknown packet type %u", pkt_type);
		return NULL;
	}

	/*
	 * Max len of packet: (original len + 4 (H5 hdr) + 2 (crc)) * 2
	 * (because bytes 0xc0 and 0xdb are escaped, worst case is when
	 * the packet is all made of 0xc0 and 0xdb) + 2 (0xc0
	 * delimiters at start and end).
	 */
	nskb = skb_alloc((len + 6) * 2 + 2);
	if (!nskb)
		return NULL;

	h5_slip_delim(nskb);

	hdr[0] = h5->tx_ack << 3;

	if (pkt_type == HCI_ACLDATA_PKT || pkt_type == HCI_COMMAND_PKT) {
		hdr[0] |= 1 << 7;
		hdr[0] |= h5->tx_seq;
		h5->tx_seq = (h5->tx_seq + 1) & 0x07;
	}

	hdr[1] = pkt_type | ((len & 0x0f) << 4);
	hdr[2] = len >> 4;
	hdr[3] = ~((hdr[0] + hdr[1] + hdr[2]) & 0xff);

	for (i = 0; i < 4; i++)
		h5_slip_one_byte(nskb, hdr[i]);

	for (i = 0; i < len; i++)
		h5_slip_one_byte(nskb, data[i]);

	h5_slip_delim(nskb);

	return nskb;
}

static int hci_read_check(int fd, void *buf, int count)
{
	int res;

	do {
		res = read(fd, buf, count);
		if (res != -1) {
			buf += res;
			count -= res;
			return res;
		}
	} while (count && (errno == 0 || errno == EINTR));

	return res;
}

static void hci_cmd_sig_alarm(int sig)
{
	if (hu->cmd_timeout_count < hu->cmd_timeout) {
		hu->cmd_timeout_count++;
		h5_cmd_send(hu, hu->cmd_buf, hu->cmd_len);
		hu->cmd_state = cmd_has_sent;
		alarm(1);
		return;
	}

	tcflush(hu->tty_fd, TCIOFLUSH);
	exit(1);
}

static void __hci_cmd_sync(struct hci_uart *hu, uint16_t opcode, size_t plen,
		const void *param, int timeout)
{
	unsigned char buf[16];
	struct sigaction sa;
	int ret;

	hu->cmd_state = cmd_not_send;
	hu->cmd_timeout = timeout;
	hu->cmd_timeout_count = 0;

	hu->cmd_buf[0] = opcode & 0xff;
	hu->cmd_buf[1] = (opcode >> 8) & 0xff;
	hu->cmd_buf[2] = plen;
	if (plen)
		memcpy(hu->cmd_buf + 3, param, plen);
	hu->cmd_len = 3 + plen;

	alarm(0);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = hci_cmd_sig_alarm;
	sigaction(SIGALRM, &sa, NULL);

	hci_cmd_sig_alarm(0);

	while (hu->cmd_state != event_received) {
		if ((ret = hci_read_check(hu->tty_fd, buf, sizeof(buf))) == -1)
				return;

		h5_recv(hu, buf, ret);
	}

	alarm(0);
}

static int rtk_download_firmware(struct hci_uart *hu,
		const unsigned char *fw_data, int fw_len)
{
	struct h5 *h5 = hu->priv;
	rtk_download_request *dl_cmd;
	int frag_num = fw_len / RTK_FRAG_LEN + 1;
	int frag_len = RTK_FRAG_LEN;
	int i;

	dl_cmd = malloc(sizeof(*dl_cmd));
	if (!dl_cmd)
		return -1;

	h5->state = H5_PATCH;

	for (i = 0; i < frag_num; i++) {
		rtk_download_response *dl_rsp;

		BT_DBG("download fw (%i/%i)", i, frag_num);

		dl_cmd->index = i;

		if (i == (frag_num - 1)) {
			dl_cmd->index |= 0x80;
			frag_len = fw_len % RTK_FRAG_LEN;
		}
		memcpy(dl_cmd->data, fw_data, frag_len);

		__hci_cmd_sync(hu, 0xfc20, frag_len + 1, dl_cmd, 10);
		dl_rsp = (rtk_download_response *)hu->cmd_buf;
		if (dl_rsp->status)
			return -1;

		fw_data += RTK_FRAG_LEN;
	}

	h5_ack_send(hu, NULL, 0);
	return 0;
}

static int rtk_parse_firmware(struct hci_uart *hu, unsigned char **fw_data,
		int fw_len)
{
	const uint8_t extension_sig[4] = { 0x51, 0x04, 0xfd, 0x77 };
	read_rom_version_rp *rsp;
	rtk_epatch_header *epatch_info;
	unsigned char *buf;
	const unsigned char *fwptr, *chip_id_base;
	const unsigned char *patch_length_base, *patch_offset_base;
	uint8_t opcode, length, data;
	uint32_t patch_offset = 0;
	uint16_t patch_length;
	size_t min_size;
	int project_id = -1;
	int i;
	const uint16_t project_id_to_lmp_subver[] = {
		RTK_ROM_LMP_8723A,
		RTK_ROM_LMP_8723B,
		RTK_ROM_LMP_8723B2,
		RTK_ROM_LMP_8821A,
		RTK_ROM_LMP_8761A,
	};

	__hci_cmd_sync(hu, HCI_VENDOR_READ_ROM_VERSION, 0, NULL, 10);
	rsp = (read_rom_version_rp *)hu->cmd_buf;
	if (rsp->status)
		hu->rom_version = 0;
	else
		hu->rom_version = rsp->version;

	BT_DBG("lmp_version=%x rom_version=%x",
			hu->lmp_subver, hu->rom_version);

	min_size = sizeof(*epatch_info) + sizeof(extension_sig) + 3;
	if (fw_len < min_size)
		return -1;

	fwptr = *fw_data + fw_len - sizeof(extension_sig);
	if (memcmp(fwptr, extension_sig, 4) != 0)
		return -1;

	while (fwptr >= *fw_data + (sizeof(*epatch_info) + 3)) {
		opcode = *--fwptr;
		length = *--fwptr;
		data = *--fwptr;

		BT_DBG("opcode=%x length=%x data=%x", opcode, length, data);

		if (opcode == 0xff)
			break;

		if (length == 0)
			return -1;

		if (opcode == 0 && length == 1) {
			project_id = data;
			break;
		}

		fwptr -= length;
	}

	if (project_id < 0)
		return -1;

	if (project_id > sizeof(project_id_to_lmp_subver)/sizeof(project_id_to_lmp_subver[0]))
		return -1;

	if (hu->lmp_subver != project_id_to_lmp_subver[project_id])
		return -1;

	epatch_info = (rtk_epatch_header *)*fw_data;
	if (memcmp(epatch_info->signature, RTK_EPATCH_SIGNATURE, 8) != 0)
		return -1;

	BT_DBG("fw_version=%x, num_patches=%i",
			epatch_info->fw_version, epatch_info->num_patches);

	min_size += 8 * epatch_info->num_patches;
	if (fw_len < min_size)
		return -1;

	chip_id_base = *fw_data + sizeof(*epatch_info);
	patch_length_base = chip_id_base +
			(sizeof(uint16_t) * epatch_info->num_patches);
	patch_offset_base = patch_length_base +
			(sizeof(uint16_t) * epatch_info->num_patches);
	for (i = 0; i < epatch_info->num_patches; i++) {
		uint16_t chip_id = le16_to_cpu(*(uint16_t *)(chip_id_base +
				(i * sizeof(uint16_t))));
		if (chip_id == hu->rom_version + 1) {
			patch_length = le16_to_cpu(*(uint16_t *)(patch_length_base +
					(i * sizeof(uint16_t))));
			patch_offset = le32_to_cpu(*(uint32_t *)(patch_offset_base +
					(i * sizeof(uint32_t))));
			break;
		}
	}

	if (!patch_offset)
		return -1;

	BT_DBG("length=%x offset=%x index %i", patch_length, patch_offset, i);

	min_size = patch_offset + patch_length;
	if (fw_len < min_size)
		return -1;

	buf = malloc(patch_length);
	if (!buf)
		return -1;
	memcpy(buf, *fw_data + patch_offset, patch_length);
	free(*fw_data);

	memcpy(buf + patch_length - 4, &epatch_info->fw_version, 4);

	*fw_data = buf;
	return patch_length;
}

static int rtk_request_firmware(const char *filename, unsigned char **fw_data)
{
	unsigned char *buf;
	struct stat st;
	size_t len;
	int fd;

	if (stat(filename, &st) < 0) {
		BT_ERR("can't access firmware:%s", filename);
		return -1;
	}

	len = st.st_size;
	buf = malloc(len);
	if (!buf)
		return -1;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		free(buf);
		return -1;
	}

	if (read(fd, buf, len) != len) {
		free(buf);
		close(fd);
		return -1;
	}

	close(fd);

	*fw_data = buf;

	return len;
}

static int rtk_patch(struct hci_uart *hu)
{
	read_local_version_rp *rsp;
	const char *fw_name;
	unsigned char *fw_data;
	int ret;

	__hci_cmd_sync(hu, HCI_VENDOR_READ_LMP_VERSION, 0, NULL, 10);
	rsp = (read_local_version_rp *)hu->cmd_buf;
	if (rsp->status) {
		BT_ERR("fw version event failed (%02x)", rsp->status);
		return -1;
	}
	hu->lmp_subver = le16_to_cpu(rsp->lmp_subver);

	switch (hu->lmp_subver) {
	case RTK_ROM_LMP_8723B:
		fw_name = FIRMWARE_DIR"rtl_bt/rtl8723b_fw.bin";
		break;
	default:
		BT_ERR("not support yet!");
		return -1;
	}

	ret = rtk_request_firmware(fw_name, &fw_data);
	if (ret < 0)
		return ret;

	ret = rtk_parse_firmware(hu, &fw_data, ret);
	if (ret < 0)
		goto out;

	ret = rtk_download_firmware(hu, fw_data, ret);

out:
	free(fw_data);
	return ret;
}

static void rtk_tshy_sig_alarm(int sig)
{
	const unsigned char sync_req[] = { 0x01, 0x7e };
	static int retries = 0;

	if (retries < 10) {
		retries++;
		h5_link_control(hu, sync_req, sizeof(sync_req));
		alarm(1);
		return;
	}

	tcflush(hu->tty_fd, TCIOFLUSH);
	fprintf(stderr, "H5 initialization timed out\n");
	exit(1);
}

static void rtk_tconf_sig_alarm(int sig)
{
	const unsigned char conf_req[] = { 0x03, 0xfc, 0x01 };
	static int retries = 0;

	if (retries < 10) {
		retries++;
		h5_link_control(hu, conf_req, sizeof(conf_req));
		alarm(1);
		return;
	}

	tcflush(hu->tty_fd, TCIOFLUSH);
	fprintf(stderr, "H5 initialization timed out\n");
	exit(1);
}

static int rtk_init_h5(struct hci_uart *hu)
{
	struct h5 *h5 = hu->priv;
	unsigned char buf[16];
	struct sigaction sa;
	int ret;

	hu->ti->c_cflag |= PARENB;
	hu->ti->c_cflag &= ~(PARODD);

	if (tcsetattr(hu->tty_fd, TCSANOW, hu->ti) < 0) {
		perror("Can't set port settings");
		return -1;
	}

	alarm(0);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = rtk_tshy_sig_alarm;
	sigaction(SIGALRM, &sa, NULL);

	h5->state = H5_SYNC;

	rtk_tshy_sig_alarm(0);

	while (h5->state == H5_SYNC) {
		if ((ret = hci_read_check(hu->tty_fd, buf, sizeof(buf))) == -1)
			return -1;

		h5_recv(hu, buf, ret);
	}

	alarm(0);
	sa.sa_handler = rtk_tconf_sig_alarm;
	sigaction(SIGALRM, &sa, NULL);
	alarm(1);

	while (h5->state == H5_CONFIG) {
		if ((ret = hci_read_check(hu->tty_fd, buf, sizeof(buf))) == -1)
			return -1;

		h5_recv(hu, buf, ret);
	}

	h5_ack_send(hu, NULL, 0);
	return 0;
}

int rtk_init(int fd, int speed, char *bdaddr, struct termios *ti)
{
	struct h5 *h5;
	int ret = -1;

	hu = malloc(sizeof(*hu));
	if (!hu)
		return -1;

	memset(hu, 0, sizeof(*hu));

	h5 = malloc(sizeof(*h5));
	if (!h5)
		goto err;

	memset(h5, 0, sizeof(*h5));

	hu->tty_fd = fd;
	hu->ti = ti;
	hu->bdaddr = bdaddr;
	hu->priv = h5;

	h5_reset_rx(h5);

	ret = rtk_init_h5(hu);
	if (ret < 0)
		goto err_h5;

	ret = rtk_patch(hu);

err_h5:
	free(h5);
err:
	free(hu);

	return ret;
}

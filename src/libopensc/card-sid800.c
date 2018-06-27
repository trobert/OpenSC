/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* Initially written by Thibaut Robert (thibaut.robert@gmail.com) 2018 */

#include <stdlib.h>

#include "internal.h"

typedef struct sid800_private {
	unsigned short object_id;
} sid800_private_t;

#define SID800_DATA(card) ((sid800_private_t*)card->drv_data)

static struct sc_atr_table sid800_atrs[] = {
	{
 	         "3b:0f:80:22:15:e1:5a:00:20:00:30:21:03:31:21:03:00",
		 "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:fe:ff:ff:ff:ff:ff:ff", 
		 "sid800", SC_CARD_TYPE_SID800, 0, NULL
	},
	{ 
	         "3b:6f:00:ff:52:53:41:53:65:63:75:72:49:44:28:52:29:31:30",
		 "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff", 
		 "sid800", SC_CARD_TYPE_SID800, 0, NULL
	},
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations sid800_ops, *iso_ops;

static struct sc_card_driver sid800_drv = {
	"RSA SecurID SID800 token", "sid800", &sid800_ops, NULL, 0, NULL
};

static int sid800_select_file(sc_card_t *card, const sc_path_t *in_path,
			      sc_file_t **file_out)
{
	struct sc_apdu apdu;
	struct sc_file *file;
	unsigned short objid;
	int r;
	
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (card == NULL || in_path == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
       
	if (in_path->type != SC_PATH_TYPE_PATH && (in_path->type != SC_PATH_TYPE_FILE_ID || in_path->len != 2))
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	if (in_path->aid.len) {
		/* First, select the application */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 4, 0);
		apdu.data = in_path->aid.value;
		apdu.datalen = in_path->aid.len;
		apdu.lc = in_path->aid.len;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
			LOG_FUNC_RETURN(card->ctx, r);
	}

	if (in_path->type == SC_PATH_TYPE_PATH) {
		SID800_DATA(card)->object_id = 0;
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}
		
	objid = bebytes2ushort(in_path->value);
	SID800_DATA(card)->object_id = objid;

	if (file_out) {
		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		file->id = objid;

		*file_out = file;
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}	
		
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);	
}

static int sid800_read_binary(struct sc_card *card, unsigned int idx, u8 *buf, size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	sid800_private_t *priv = SID800_DATA(card);
	u8 fileid[2];
	int r;
	
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (!priv->object_id)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
		
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x14,
		       idx >> 8, idx & 0xFF);
	apdu.cla = 0x80;
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = ushort2bebytes(fileid, priv->object_id);
	apdu.le = count;
	apdu.resp = buf;
	apdu.resplen = count;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);

	if (r == SC_ERROR_FILE_END_REACHED)
		LOG_FUNC_RETURN(card->ctx, apdu.resplen);
	LOG_TEST_RET(card->ctx, r, "Check SW error");

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);		
}

static int sid800_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	int r;

	card->cla = 0x80;
	r = iso_ops->pin_cmd(card, data, tries_left);
	card->cla = 0x00;

	return r;
}

static int sid800_init(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	
	if (card->drv_data) {
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	card->drv_data = calloc(1, sizeof(sid800_private_t));

	if (!card->drv_data)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int sid800_finish(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (card->drv_data)
		free(card->drv_data);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}	
	
static int sid800_match_card(sc_card_t *card)
{
	int i;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	i = _sc_match_atr(card, sid800_atrs, &card->type);
	if (i < 0)
		return 0;		

	return 1;
}

struct sc_card_driver * sc_get_sid800_driver(void)
{
  	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	iso_ops = iso_drv->ops;
	sid800_ops = *iso_drv->ops;
	sid800_ops.init = sid800_init;
	sid800_ops.finish = sid800_finish;
	sid800_ops.match_card = sid800_match_card;
	sid800_ops.select_file = sid800_select_file;
	sid800_ops.read_binary = sid800_read_binary;
	sid800_ops.pin_cmd = sid800_pin_cmd;
	return &sid800_drv;
}

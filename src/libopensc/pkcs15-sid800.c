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

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "pkcs15.h"
#include "compression.h"

static struct sc_aid pub_container = {
	{0xA0,0x00,0x00,0x00,0x63,0x86,0x02,0x00,0x06}, 9};

static int sc_pkcs15emu_sid800_init(sc_pkcs15_card_t *p15card)
{
	u8 buf[4096];
	u8* certfile = NULL;
	size_t compressed_len, certfile_len;
	int r, file_id;
	
	sc_card_t *card = p15card->card;
	sc_path_t path = {
	  {0, 0}, 0, 0, -1, SC_PATH_TYPE_FILE_ID, pub_container};

	sc_pkcs15_cert_info_t cert_info;
	sc_pkcs15_object_t cert_obj;
	
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	p15card->opts.use_file_cache = 1;	

	if (p15card->tokeninfo->label != NULL)
		free(p15card->tokeninfo->label);
	p15card->tokeninfo->label = strdup("SecurID (sid800)");
	if (p15card->tokeninfo->serial_number != NULL)
		free(p15card->tokeninfo->serial_number);
	p15card->tokeninfo->serial_number = strdup("1234");
	if (p15card->tokeninfo->manufacturer_id != NULL)
		free(p15card->tokeninfo->manufacturer_id);
	p15card->tokeninfo->manufacturer_id = strdup("RSA");

	for (file_id = 0x6331; file_id<=0x6337; file_id++) {
		path.len = 0;
		sc_append_file_id(&path, file_id);
		sc_select_file(card, &path, NULL);
		r = sc_read_binary(card, 0, buf, 4096, 0);
		if (r <= 0)
			continue;
		
		compressed_len = r;
		sc_decompress_alloc(&certfile, &certfile_len,
				    buf, compressed_len, COMPRESSION_ZLIB);

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj,  0, sizeof(cert_obj));

		cert_info.id.value[0] = file_id - 0x6331;
		cert_info.id.len = 1;
		cert_info.path = path;

		sc_pkcs15_cache_file(p15card, &path, certfile, certfile_len);
		sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	}
  	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int sid800_detect_card(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (card->type < SC_CARD_TYPE_SID800
		|| card->type >= SC_CARD_TYPE_SID800+1000)
		return SC_ERROR_INVALID_CARD;
	return SC_SUCCESS;
}

int sc_pkcs15emu_sid800_init_ex(sc_pkcs15_card_t *p15card,
				struct sc_aid *aid,
				sc_pkcs15emu_opt_t *opts)
{
	sc_card_t  *card = p15card->card;
	sc_context_t *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		rv = sc_pkcs15emu_sid800_init(p15card);
	else {
		rv = sid800_detect_card(p15card);
		if (rv)
			LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);
		rv = sc_pkcs15emu_sid800_init(p15card);
	}

	LOG_FUNC_RETURN(ctx, rv);
}

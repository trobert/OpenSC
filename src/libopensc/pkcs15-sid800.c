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

static struct sc_aid pub_container = {
	{0xA0,0x00,0x00,0x00,0x63,0x86,0x02,0x00,0x06}, 9};

static int sc_pkcs15emu_sid800_init(sc_pkcs15_card_t *p15card)
{
	u8 buf[1024];
	sc_card_t *card = p15card->card;
	sc_path_t path = {
	  {0, 0}, 0, 0, 0, SC_PATH_TYPE_FILE_ID, pub_container};
	
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (p15card->tokeninfo->label != NULL)
		free(p15card->tokeninfo->label);
	p15card->tokeninfo->label = strdup("SecurID (sid800)");
	if (p15card->tokeninfo->manufacturer_id != NULL)
		free(p15card->tokeninfo->manufacturer_id);
	p15card->tokeninfo->manufacturer_id = strdup("RSA");

	sc_append_file_id(&path, 0x6331);
	sc_select_file(card, &path, NULL);
	sc_read_binary(card, 0, buf, 1024, 0);
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

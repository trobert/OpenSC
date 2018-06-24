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

#include "internal.h"

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

static struct sc_card_operations sid800_ops;

static struct sc_card_driver sid800_drv = {
	"RSA SecurID SID800 token", "sid800", &sid800_ops, NULL, 0, NULL
};

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
	sid800_ops = *iso_drv->ops;
	sid800_ops.match_card = sid800_match_card;
	return &sid800_drv;
}

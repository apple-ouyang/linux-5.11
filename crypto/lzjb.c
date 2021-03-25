/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * We keep our own copy of this algorithm for 3 main reasons:
 *	1. If we didn't, anyone modifying common/os/compress.c would
 *         directly break our on disk format
 *	2. Our version of lzjb does not have a number of checks that the
 *         common/os version needs and uses
 *	3. We initialize the lempel to ensure deterministic results,
 *	   so that identical blocks can always be deduplicated.
 * In particular, we are adding the "feature" that compress() can
 * take a destination buffer size and returns the compressed length, or the
 * source length if compression would overflow the destination buffer.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/lzjb.h>
#include <crypto/internal/scompress.h>
#include <linux/lz4.h>

// lzjb2010.c 源码
#define NBBY 8
#define	MATCH_BITS	6
#define	MATCH_MIN	3
#define	MATCH_MAX	((1 << MATCH_BITS) + (MATCH_MIN - 1))
#define	OFFSET_MASK	((1 << (16 - MATCH_BITS)) - 1)
#define	LEMPEL_SIZE	1024

/*ARGSUSED*/
static int
lzjb_compress2010(uchar_t *s_start, uchar_t *d_start, unsigned int s_len, unsigned int d_len, int n)
{
	uchar_t *src = s_start;
	uchar_t *dst = d_start;
	uchar_t *cpy, *copymap;
	int copymask = 1 << (NBBY - 1);
	int mlen, offset, hash;
	uint16_t *hp;
	uint16_t lempel[LEMPEL_SIZE] = { 0 };

	while (src < (uchar_t *)s_start + s_len) {
		if ((copymask <<= 1) == (1 << NBBY)) {
			if (dst >= (uchar_t *)d_start + d_len - 1 - 2 * NBBY)
				return (s_len);
			copymask = 1;
			copymap = dst;
			*dst++ = 0;
		}
		if (src > (uchar_t *)s_start + s_len - MATCH_MAX) {
			*dst++ = *src++;
			continue;
		}
		hash = (src[0] << 16) + (src[1] << 8) + src[2];
		hash += hash >> 9;
		hash += hash >> 5;
		hp = &lempel[hash & (LEMPEL_SIZE - 1)];
		offset = (uintptr_t)(src - *hp) & OFFSET_MASK;
		*hp = (uint16_t)(uintptr_t)src;
		cpy = src - offset;
		if (cpy >= (uchar_t *)s_start && cpy != src &&
		    src[0] == cpy[0] && src[1] == cpy[1] && src[2] == cpy[2]) {
			*copymap |= copymask;
			for (mlen = MATCH_MIN; mlen < MATCH_MAX; mlen++)
				if (src[mlen] != cpy[mlen])
					break;
			*dst++ = ((mlen - MATCH_MIN) << (NBBY - MATCH_BITS)) |
			    (offset >> NBBY);
			*dst++ = (uchar_t)offset;
			src += mlen;
		} else {
			*dst++ = *src++;
		}
	}
	return (dst - (uchar_t *)d_start);
}

/*ARGSUSED*/
static int
lzjb_decompress2010(uchar_t *s_start, uchar_t *d_start, unsigned int s_len, unsigned int d_len, int n)
{
	uchar_t *src = s_start;
	uchar_t *dst = d_start;
	uchar_t *d_end = (uchar_t *)d_start + d_len;
	uchar_t *cpy, copymap;
	int copymask = 1 << (NBBY - 1);

	while (dst < d_end) {
		if ((copymask <<= 1) == (1 << NBBY)) {
			copymask = 1;
			copymap = *src++;
		}
		if (copymap & copymask) {
			int mlen = (src[0] >> (NBBY - MATCH_BITS)) + MATCH_MIN;
			int offset = ((src[0] << NBBY) | src[1]) & OFFSET_MASK;
			src += 2;
			if ((cpy = dst - offset) < (uchar_t *)d_start)
				return (-1);
			while (--mlen >= 0 && dst < d_end)
				*dst++ = *cpy++;
		} else {
			*dst++ = *src++;
		}
	}
	return (dst - (uchar_t *)d_start);
}


// 正常代码开始

struct lzjb_ctx {
	void *lzjb_comp_mem;
};

static void *lzjb_alloc_ctx(struct crypto_scomp *tfm)
{
	void *ctx;
    // 这里先用 lz4 的代替
	ctx = vmalloc(LZ4_MEM_COMPRESS);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	return ctx;
}

static int lzjb_init(struct crypto_tfm *tfm)
{
	struct lzjb_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->lzjb_comp_mem = lzjb_alloc_ctx(NULL);
	if (IS_ERR(ctx->lzjb_comp_mem))
		return -ENOMEM;

	return 0;
}

static void lzjb_free_ctx(struct crypto_scomp *tfm, void *ctx)
{
	vfree(ctx);
}

static void lzjb_exit(struct crypto_tfm *tfm)
{
	struct lzjb_ctx *ctx = crypto_tfm_ctx(tfm);

	lzjb_free_ctx(NULL, ctx->lzjb_comp_mem);
}


static int __lzjb_compress_crypto(const u8 *src, unsigned int slen,
				 u8 *dst, unsigned int *dlen, void *ctx)
{
	int out_len = lzjb_compress2010(src, dst,
		slen, *dlen, ctx);

	if (!out_len)
		return -EINVAL;

	*dlen = out_len;
	return 0;
}

// 实际上，这俩函数是一样的。
static int lzjb_scompress(struct crypto_scomp *tfm, const u8 *src,
			 unsigned int slen, u8 *dst, unsigned int *dlen,
			 void *ctx)
{
	return __lzjb_compress_crypto(src, slen, dst, dlen, ctx);
}

static int lzjb_compress_crypto(struct crypto_tfm *tfm, const u8 *src,
			       unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct lzjb_ctx *ctx = crypto_tfm_ctx(tfm);

	return __lzjb_compress_crypto(src, slen, dst, dlen, ctx->lzjb_comp_mem);
}


static int __lzjb_decompress_crypto(const u8 *src, unsigned int slen,
				   u8 *dst, unsigned int *dlen, void *ctx)
{
    // ctx 是啥都行，反正没有用到这个
	int out_len = lzjb_decompress2010(src, dst, slen, *dlen, ctx);

	if (out_len < 0)
		return -EINVAL;

	*dlen = out_len;
	return 0;
}

static int lzjb_sdecompress(struct crypto_scomp *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int *dlen,
			   void *ctx)
{
	return __lzjb_decompress_crypto(src, slen, dst, dlen, NULL);
}

static int lzjb_decompress_crypto(struct crypto_tfm *tfm, const u8 *src,
				 unsigned int slen, u8 *dst,
				 unsigned int *dlen)
{
	return __lzjb_decompress_crypto(src, slen, dst, dlen, NULL);
}


static struct crypto_alg alg_lzjb = {
	.cra_name		= "lzjb",
	.cra_driver_name	= "lzjb-generic",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct lzjb_ctx),
	.cra_module		= THIS_MODULE,
	.cra_init		= lzjb_init,
	.cra_exit		= lzjb_exit,
	.cra_u			= { .compress = {
	.coa_compress		= lzjb_compress_crypto,
	.coa_decompress		= lzjb_decompress_crypto } }
};

static struct scomp_alg scomp = {
	.alloc_ctx		= lzjb_alloc_ctx,
	.free_ctx		= lzjb_free_ctx,
	.compress		= lzjb_scompress,
	.decompress		= lzjb_sdecompress,
	.base			= {
		.cra_name	= "lzjb",
		.cra_driver_name = "lzjb-scomp",
		.cra_module	 = THIS_MODULE,
	}
};

static int __init lzjb_mod_init(void)
{
	int ret;

	ret = crypto_register_alg(&alg_lzjb);
	if (ret)
		return ret;

	ret = crypto_register_scomp(&scomp);
	if (ret) {
		crypto_unregister_alg(&alg_lzjb);
		return ret;
	}

	return ret;
}

static void __exit lzjb_mod_fini(void)
{
	crypto_unregister_alg(&alg_lzjb);
	crypto_unregister_scomp(&scomp);
}

subsys_initcall(lzjb_mod_init);
module_exit(lzjb_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lzjb Compression Algorithm");
MODULE_ALIAS_CRYPTO("lzjb");

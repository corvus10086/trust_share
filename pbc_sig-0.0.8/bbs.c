//see Boneh, Boyen and Shacham, "Short Group Signatures"
#include <pbc/pbc.h>
#include "inc/bbs.h"
#include "inc/hash.h"
#include <stdio.h>
#include <string.h>

void bbs_gen_sys_param(bbs_sys_param_ptr param, pairing_ptr pairing)
{
  param->pairing = pairing;
  param->signature_length = 3 * pairing->G1->fixed_length_in_bytes + 6 * pairing->Zr->fixed_length_in_bytes;
}

void bbs_gen(bbs_group_public_key_ptr gpk, bbs_manager_private_key_ptr gmsk, int n, bbs_group_private_key_t *gsk, bbs_sys_param_ptr param)
{
  pairing_ptr pairing = param->pairing;
  element_t z0;
  element_t gamma;
  int i;

  gpk->param = param;
  gmsk->param = param;
  element_init_G1(gpk->g1, pairing);
  element_init_G2(gpk->g2, pairing);
  element_init_G1(gpk->h, pairing);
  element_init_G1(gpk->u, pairing);
  element_init_G1(gpk->v, pairing);
  element_init_G2(gpk->w, pairing);
  element_init_Zr(gmsk->xi1, pairing);
  element_init_Zr(gmsk->xi2, pairing);
  element_init_Zr(z0, pairing);
  element_init_Zr(gamma, pairing);

  element_random(gpk->g2);
  element_random(gpk->g1);
  element_random(gpk->h);
  element_random(gmsk->xi1);
  element_random(gmsk->xi2);
  element_invert(z0, gmsk->xi1);
  element_pow_zn(gpk->u, gpk->h, z0);
  element_invert(z0, gmsk->xi2);
  element_pow_zn(gpk->v, gpk->h, z0);
  element_random(gamma);
  element_pow_zn(gpk->w, gpk->g2, gamma);

  for (i=0; i<n; i++) {
    gsk[i]->param = param;
    element_init_G1(gsk[i]->A, pairing);
    element_init_Zr(gsk[i]->x, pairing);

    element_random(gsk[i]->x);
    element_add(z0, gamma, gsk[i]->x);
    element_invert(z0, z0);
    element_pow_zn(gsk[i]->A, gpk->g1, z0);

    /* do some precomputation */
    /* TODO: could instead compute from e(g1,g2) ... */
    element_init_GT(gsk[i]->pr_A_g2, pairing);
    pairing_apply(gsk[i]->pr_A_g2, gsk[i]->A, gpk->g2, pairing);
  }


  /* do some precomputation */
  element_init_GT(gpk->pr_g1_g2, pairing);
  element_init_GT(gpk->pr_g1_g2_inv, pairing);
  element_init_GT(gpk->pr_h_g2, pairing);
  element_init_GT(gpk->pr_h_w, pairing);
  pairing_apply(gpk->pr_g1_g2, gpk->g1, gpk->g2, pairing);
  element_invert(gpk->pr_g1_g2_inv, gpk->pr_g1_g2);
  pairing_apply(gpk->pr_h_g2, gpk->h, gpk->g2, pairing);
  pairing_apply(gpk->pr_h_w, gpk->h, gpk->w, pairing);

  element_clear(z0);
  element_clear(gamma);
}

void bbs_sign(unsigned char *sig, int hashlen, void *hash, bbs_group_public_key_ptr gpk, bbs_group_private_key_ptr gsk)
{
  bbs_sys_param_ptr param = gpk->param;
  pairing_ptr pairing = param->pairing;
  field_ptr Fp = pairing->Zr;
  element_t T1, T2, T3;
  element_t R1, R2, R3, R4, R5;
  element_t alpha, beta;
  element_t c;
  element_t ralpha, rbeta, rx, rdelta1, rdelta2;
  element_t z0, z1;
  element_t e10, et0;
  unsigned char *writeptr = sig;
  element_init_G1(T1, pairing);
  element_init_G1(T2, pairing);
  element_init_G1(T3, pairing);
  element_init_G1(R1, pairing);
  element_init_G1(R2, pairing);
  element_init_GT(R3, pairing);
  element_init_G1(R4, pairing);
  element_init_G1(R5, pairing);

  element_init(c, Fp);
  element_init(alpha, Fp); element_random(alpha);
  element_init(beta, Fp); element_random(beta);
  //temp variables
  element_init(z0, Fp);
  element_init(z1, Fp);
  element_init_GT(et0, pairing);
  element_init_G1(e10, pairing);
  element_init(ralpha, Fp); element_random(ralpha);
  element_init(rbeta, Fp); element_random(rbeta);
  element_init(rx, Fp); element_random(rx);
  element_init(rdelta1, Fp); element_random(rdelta1);
  element_init(rdelta2, Fp); element_random(rdelta2);
  element_pow_zn(T1, gpk->u, alpha);
  element_pow_zn(T2, gpk->v, beta);
  element_add(z0, alpha, beta);

  element_pow_zn(T3, gpk->h, z0);
  element_mul(T3, T3, gsk->A);

  element_pow_zn(R1, gpk->u, ralpha);

  element_pow_zn(R2, gpk->v, rbeta);

  /*
  * rather than computing e(T3,g2), note that T3 = A h^{alpha+beta},
  * use precomputed e(A,g2) and e(h,g2), and use appropriate
  * exponentiations in GT.
  */

  //pairing_apply(et0, T3, gpk->g2, pairing);  /* precomputed */
  element_pow_zn(et0, gpk->pr_h_g2, z0); /* NB. here z0 = alpha+beta */

  element_mul(et0, et0, gsk->pr_A_g2);
  //element_pow_zn(R3, et0, rx);

  // pairing_apply(et0, gpk->h, gpk->w, pairing);  /* precomputed */
  element_add(z0, ralpha, rbeta);
  element_neg(z0, z0);
  //element_pow_zn(et0, gpk->pr_h_w, z0);
  //element_mul(R3, R3, et0);
  // pairing_apply(et0, gpk->h, gpk->g2, pairing);  /* precomputed */
  element_add(z1, rdelta1, rdelta2);
  element_neg(z1, z1);
  //element_pow_zn(et0, gpk->pr_h_g2, z1);
  //element_mul(R3, R3, et0);

  element_pow3_zn(R3, et0, rx, gpk->pr_h_w, z0, gpk->pr_h_g2, z1);

  //element_pow_zn(R4, T1, rx);
  element_neg(z0, rdelta1);
  //element_pow_zn(e10, gpk->u, z0);
  //element_mul(R4, R4, e10);
  element_pow2_zn(R4, T1, rx, gpk->u, z0);

  //element_pow_zn(R5, T2, rx);
  element_neg(z0, rdelta2);
  //element_pow_zn(e10, gpk->v, z0);
  //element_mul(R5, R5, e10);
  element_pow2_zn(R5, T2, rx, gpk->v, z0);


  element_t M;
  element_init_G1(M, pairing);
  element_from_hash(M, hash, hashlen);

  unsigned int hash_input_length = element_length_in_bytes(T1) +
  element_length_in_bytes(T2) +
  element_length_in_bytes(T3) +
  element_length_in_bytes(R1) +
  element_length_in_bytes(R2) +
  element_length_in_bytes(R3) +
  element_length_in_bytes(R4) +
  element_length_in_bytes(R5) +
  element_length_in_bytes(M);

  unsigned char *hash_input = malloc(hash_input_length);

  hash_input += element_to_bytes(hash_input, T1);
  hash_input += element_to_bytes(hash_input, T2);
  hash_input += element_to_bytes(hash_input, T3);
  hash_input += element_to_bytes(hash_input, R1);
  hash_input += element_to_bytes(hash_input, R2);
  hash_input += element_to_bytes(hash_input, R3);
  hash_input += element_to_bytes(hash_input, R4);
  hash_input += element_to_bytes(hash_input, R5);
  hash_input += element_to_bytes(hash_input, M); // Could avoid converting to bytes and from bytes
  hash_input -= hash_input_length;

  hash_ctx_t context;
  unsigned char digest[hash_length];

  hash_init(context);
  hash_update(context, hash_input, hash_input_length);
  hash_final(digest, context);
  free(hash_input);

  element_from_hash(c, digest, sizeof(digest));

  element_clear(M);

  //now the r's represent the values of the s's
  //no need to allocate yet more variables
  element_mul(z0, c, alpha);
  element_add(ralpha, ralpha, z0);

  element_mul(z0, c, beta);
  element_add(rbeta, rbeta, z0);

  element_mul(z1, c, gsk->x);
  element_add(rx, rx, z1);

  element_mul(z0, z1, alpha);
  element_add(rdelta1, rdelta1, z0);

  element_mul(z0, z1, beta);
  element_add(rdelta2, rdelta2, z0);

  writeptr += element_to_bytes(writeptr, T1);
  writeptr += element_to_bytes(writeptr, T2);
  writeptr += element_to_bytes(writeptr, T3);
  writeptr += element_to_bytes(writeptr, c);
  writeptr += element_to_bytes(writeptr, ralpha);
  writeptr += element_to_bytes(writeptr, rbeta);
  writeptr += element_to_bytes(writeptr, rx);
  writeptr += element_to_bytes(writeptr, rdelta1);
  writeptr += element_to_bytes(writeptr, rdelta2);

  #ifdef DEBUG
  element_printf("T1: %B\n", T1);
  element_printf("T2: %B\n", T2);
  element_printf("T3: %B\n", T3);
  element_printf("R1: %B\n", R1);
  element_printf("R2: %B\n", R2);
  element_printf("R3: %B\n", R3);
  element_printf("R4: %B\n", R4);
  element_printf("R5: %B\n", R5);

  element_printf("c: %B\n", c);


  #endif

  element_clear(T1);
  element_clear(T2);
  element_clear(T3);
  element_clear(R1);
  element_clear(R2);
  element_clear(R3);
  element_clear(R4);
  element_clear(R5);
  element_clear(alpha);
  element_clear(beta);
  element_clear(c);
  element_clear(ralpha);
  element_clear(rbeta);
  element_clear(rx);
  element_clear(rdelta1);
  element_clear(rdelta2);
  //clear temp variables
  element_clear(z0);
  element_clear(z1);
  element_clear(e10);
  element_clear(et0);
}

int bbs_verify(unsigned char *sig, int hashlen, void *hash, bbs_group_public_key_t gpk)
{
  bbs_sys_param_ptr param = gpk->param;
  pairing_ptr pairing = param->pairing;
  field_ptr Fp = pairing->Zr;
  element_t T1, T2, T3;
  element_t R1, R2, R3, R4, R5;
  element_t c, salpha, sbeta, sx, sdelta1, sdelta2;
  element_t e10, e20, e21, et0, z0, z1;
  unsigned char *readptr = sig;

  element_init_G1(T1, pairing);
  element_init_G1(T2, pairing);
  element_init_G1(T3, pairing);
  element_init_G1(R1, pairing);
  element_init_G1(R2, pairing);
  element_init_GT(R3, pairing);
  element_init_G1(R4, pairing);
  element_init_G1(R5, pairing);

  element_init(c, Fp);
  element_init(salpha, Fp);
  element_init(sbeta, Fp);
  element_init(sx, Fp);
  element_init(sdelta1, Fp);
  element_init(sdelta2, Fp);

  element_init_G1(e10, pairing);
  element_init_G2(e20, pairing);
  element_init_G2(e21, pairing);
  element_init_GT(et0, pairing);
  element_init(z0, Fp);
  element_init(z1, Fp);

  readptr += element_from_bytes(T1, readptr);
  readptr += element_from_bytes(T2, readptr);
  readptr += element_from_bytes(T3, readptr);
  readptr += element_from_bytes(c, readptr);
  readptr += element_from_bytes(salpha, readptr);
  readptr += element_from_bytes(sbeta, readptr);
  readptr += element_from_bytes(sx, readptr);
  readptr += element_from_bytes(sdelta1, readptr);
  readptr += element_from_bytes(sdelta2, readptr);

  element_neg(z0, c);

  //element_pow_zn(R1, gpk->u, salpha);
  //element_pow_zn(e10, T1, z0);
  //element_mul(R1, R1, e10);
  element_pow2_zn(R1, gpk->u, salpha, T1, z0);

  //element_pow_zn(R2, gpk->v, sbeta);
  //element_pow_zn(e10, T2, z0);
  //element_mul(R2, R2, e10);
  element_pow2_zn(R2, gpk->v, sbeta, T2, z0);

  element_neg(z0, sdelta1);
  //element_pow_zn(R4, gpk->u, z0);
  //element_pow_zn(e10, T1, sx);
  //element_mul(R4, R4, e10);
  element_pow2_zn(R4, gpk->u, z0, T1, sx);

  element_neg(z0, sdelta2);
  //element_pow_zn(R5, gpk->v, z0);
  //element_pow_zn(e10, T2, sx);
  //element_mul(R5, R5, e10);
  element_pow2_zn(R5, gpk->v, z0, T2, sx);


  /*
  * compute R3 more efficiently.  use precomputed e(g1,g2)^{-1},
  * e(h,g2), and e(h,w).  this leaves e(T3,g2)^sx and e(T3,w)^c;
  * compute these with one pairing as e(T3, g2^sx w^c).
  */

  //element_pow_zn(e20, gpk->g2, sx);
  //element_pow_zn(e21, gpk->w, c);
  //element_mul(e20, e20, e21);
  element_pow2_zn(e20, gpk->g2, sx, gpk->w, c);
  pairing_apply(R3, T3, e20, pairing);

  //element_pow_zn(et0, gpk->pr_g1_g2_inv, c);
  //element_mul(R3, R3, et0);

  element_add(z0, salpha, sbeta);
  element_neg(z0, z0);
  //element_pow_zn(et0, gpk->pr_h_w, z0);
  //element_mul(R3, R3, et0);

  element_add(z1, sdelta1, sdelta2);
  element_neg(z1, z1);
  //element_pow_zn(et0, gpk->pr_h_g2, z1);

  element_pow3_zn(et0, gpk->pr_g1_g2_inv, c, gpk->pr_h_w, z0, gpk->pr_h_g2, z1);
  element_mul(R3, R3, et0);

  #ifdef DEBUG
  element_printf("T1: %B\n", T1);
  element_printf("T2: %B\n", T2);
  element_printf("T3: %B\n", T3);
  element_printf("R1: %B\n", R1);
  element_printf("R2: %B\n", R2);
  element_printf("R3: %B\n", R3);
  element_printf("R4: %B\n", R4);
  element_printf("R5: %B\n", R5);
  #endif

  int result = 0;

  element_t M;
  element_init_G1(M, pairing);
  element_from_hash(M, hash, hashlen);

  unsigned int hash_input_length = element_length_in_bytes(T1) +
  element_length_in_bytes(T2) +
  element_length_in_bytes(T3) +
  element_length_in_bytes(R1) +
  element_length_in_bytes(R2) +
  element_length_in_bytes(R3) +
  element_length_in_bytes(R4) +
  element_length_in_bytes(R5) +
  element_length_in_bytes(M);

  unsigned char *hash_input = malloc(hash_input_length);

  hash_input += element_to_bytes(hash_input, T1);
  hash_input += element_to_bytes(hash_input, T2);
  hash_input += element_to_bytes(hash_input, T3);
  hash_input += element_to_bytes(hash_input, R1);
  hash_input += element_to_bytes(hash_input, R2);
  hash_input += element_to_bytes(hash_input, R3);
  hash_input += element_to_bytes(hash_input, R4);
  hash_input += element_to_bytes(hash_input, R5);
  hash_input += element_to_bytes(hash_input, M); // Could avoid converting to bytes and from bytes
  hash_input -= hash_input_length;

  hash_ctx_t context;
  unsigned char digest[hash_length];

  hash_init(context);
  hash_update(context, hash_input, hash_input_length);
  hash_final(digest, context);
  free(hash_input);

  element_t c1;
  element_init(c1, Fp);
  element_from_hash(c1, digest, sizeof(digest));


  if (!element_cmp(c, c1)) {
    result = 1;
  }

  element_clear(M);
  element_clear(c1);

  element_clear(T1);
  element_clear(T2);
  element_clear(T3);
  element_clear(R1);
  element_clear(R2);
  element_clear(R3);
  element_clear(R4);
  element_clear(R5);
  element_clear(c);
  element_clear(salpha);
  element_clear(sbeta);
  element_clear(sx);
  element_clear(sdelta1);
  element_clear(sdelta2);
  element_clear(e10);
  element_clear(e20);
  element_clear(e21);
  element_clear(et0);
  element_clear(z0);
  element_clear(z1);

  return result;
}

int bbs_open(element_t A, bbs_group_public_key_t gpk, bbs_manager_private_key_t gmsk, int hashlen, void *hash, unsigned char *sig)
{
  bbs_sys_param_ptr param = gpk->param;
  pairing_ptr pairing = param->pairing;
  field_ptr Fp = pairing->Zr;
  element_t T1, T2, T3;
  element_t R1, R2, R3, R4, R5;
  element_t c, salpha, sbeta, sx, sdelta1, sdelta2;
  element_t e10, et0, z0;
  unsigned char *readptr = sig;
  int result;
  UNUSED_VAR (hashlen);
  UNUSED_VAR (hash);

  //TODO: consolidate with verify
  element_init_G1(T1, pairing);
  element_init_G1(T2, pairing);
  element_init_G1(T3, pairing);
  element_init_G1(R1, pairing);
  element_init_G1(R2, pairing);
  element_init_GT(R3, pairing);
  element_init_G1(R4, pairing);
  element_init_G1(R5, pairing);

  element_init(c, Fp);
  element_init(salpha, Fp);
  element_init(sbeta, Fp);
  element_init(sx, Fp);
  element_init(sdelta1, Fp);
  element_init(sdelta2, Fp);

  element_init_G1(e10, pairing);
  element_init_GT(et0, pairing);
  element_init(z0, Fp);

  readptr += element_from_bytes(T1, readptr);
  readptr += element_from_bytes(T2, readptr);
  readptr += element_from_bytes(T3, readptr);
  readptr += element_from_bytes(c, readptr);
  readptr += element_from_bytes(salpha, readptr);
  readptr += element_from_bytes(sbeta, readptr);
  readptr += element_from_bytes(sx, readptr);
  readptr += element_from_bytes(sdelta1, readptr);
  readptr += element_from_bytes(sdelta2, readptr);

  element_neg(z0, c);
  element_pow_zn(R1, gpk->u, salpha);
  element_pow_zn(e10, T1, z0);
  element_mul(R1, R1, e10);

  element_pow_zn(R2, gpk->v, sbeta);
  element_pow_zn(e10, T2, z0);
  element_mul(R2, R2, e10);

  element_neg(z0, sdelta1);
  element_pow_zn(R4, gpk->u, z0);
  element_pow_zn(e10, T1, sx);
  element_mul(R4, R4, e10);

  element_neg(z0, sdelta2);
  element_pow_zn(R5, gpk->v, z0);
  element_pow_zn(e10, T2, sx);
  element_mul(R5, R5, e10);

  pairing_apply(R3, T3, gpk->w, pairing);
  pairing_apply(et0, gpk->g1, gpk->g2, pairing);
  element_invert(et0, et0);
  element_mul(R3, R3, et0);
  element_pow_zn(R3, R3, c);

  pairing_apply(et0, T3, gpk->g2, pairing);
  element_pow_zn(et0, et0, sx);
  element_mul(R3, R3, et0);

  element_add(z0, salpha, sbeta);
  element_neg(z0, z0);
  pairing_apply(et0, gpk->h, gpk->w, pairing);
  element_pow_zn(et0, et0, z0);
  element_mul(R3, R3, et0);

  element_add(z0, sdelta1, sdelta2);
  element_neg(z0, z0);
  pairing_apply(et0, gpk->h, gpk->g2, pairing);
  element_pow_zn(et0, et0, z0);
  element_mul(R3, R3, et0);

  //if mismatch result = 0;
  //} else {

  element_pow_zn(A, T1, gmsk->xi1);
  element_pow_zn(e10, T2, gmsk->xi2);
  element_mul(A, A, e10);
  element_invert(A, A);
  element_mul(A, A, T3);
  result =1;
  //}

  element_clear(T1);
  element_clear(T2);
  element_clear(T3);
  element_clear(R1);
  element_clear(R2);
  element_clear(R3);
  element_clear(R4);
  element_clear(R5);
  element_clear(c);
  element_clear(salpha);
  element_clear(sbeta);
  element_clear(sx);
  element_clear(sdelta1);
  element_clear(sdelta2);
  element_clear(e10);
  element_clear(et0);
  element_clear(z0);

  return result;
}

void bbs_free_gpk(bbs_group_public_key_ptr gpk)
{
  element_clear(gpk->g1);
  element_clear(gpk->g2);

  element_clear(gpk->h);
  element_clear(gpk->u);
  element_clear(gpk->v);
  element_clear(gpk->w);

  element_clear(gpk->pr_g1_g2);
  element_clear(gpk->pr_h_g2);
  element_clear(gpk->pr_h_w);
  element_clear(gpk->pr_g1_g2_inv);
}

void bbs_free_gsk(bbs_group_private_key_t *gsk, int n)
{
  int i = 0;
  for(i = 0; i < n; i++) {
    element_clear(gsk[i]->A);
    element_clear(gsk[i]->x);
    element_clear(gsk[i]->pr_A_g2);
  }
}

void bbs_free_gmsk(bbs_manager_private_key_ptr gmsk)
{
  element_clear(gmsk->xi1);
  element_clear(gmsk->xi2);
}

void out(element_t elem, FILE *myfile)
{
  int sz = element_length_in_bytes(elem);
  fwrite(&sz, 4, 1, myfile);
  unsigned char* data = pbc_malloc(sz);
  if(!data) printf("DATA IS NULL\n");
  element_to_bytes(data, elem);
  fwrite(data, sz, 1, myfile);
  pbc_free(data);
}

void in(element_t elem, FILE *myfile) {
  int sz;
  fread(&sz, 4, 1, myfile);

  unsigned char* data = pbc_malloc(sz);
  fread(data, sz, 1, myfile);

  element_from_bytes(elem, data);
  pbc_free(data);
}

void load_std_params(bbs_sys_param_t sp)
{
    pairing_t pairing;

    FILE *curveFile = fopen("d201.param", "r");
    char param_string[16384];
    size_t count = fread(param_string, 1, 16384, curveFile);
    fclose(curveFile);
    pairing_init_set_buf(pairing, param_string, count);

    bbs_gen_sys_param(sp, pairing);
}

void serialize_public_key(bbs_group_public_key_ptr gpk,
    char* pub_key_bytes, int* pub_key_bytes_len)
{
    printf("From C : PUB KEY Serialization !\n");
    size_t size;
    char *bp;
    FILE* stream = open_memstream(&bp, &size);
    printf("From C : PUB KEY Serialization - stream opened!\n");
    out(gpk->g2, stream);
    out(gpk->g1, stream);
    out(gpk->h, stream);
    out(gpk->u, stream);
    out(gpk->v, stream);
    out(gpk->w, stream);
    out(gpk->pr_g1_g2, stream);
    out(gpk->pr_h_g2, stream);
    out(gpk->pr_h_w, stream);
    out(gpk->pr_g1_g2_inv, stream);
    printf("From C : PUB KEY Serialization - stuff written!\n");
    fclose(stream);
    printf("From C : PUB KEY Serialization - stream closed!\n");

    (*pub_key_bytes_len) = (int)size;
    memcpy(pub_key_bytes, bp, size);
    printf("From C : PUB KEY Serialization - finalized!\n");
}

void deserialize_public_key(bbs_group_public_key_ptr gpk,
    unsigned char* pub_key_bytes, int pub_key_bytes_len)
{
    pairing_ptr pairing;
    pairing = gpk->param->pairing;
    element_init_G1(gpk->g1, pairing);
    element_init_G2(gpk->g2, pairing);
    element_init_G1(gpk->h, pairing);
    element_init_G1(gpk->u, pairing);
    element_init_G1(gpk->v, pairing);
    element_init_G2(gpk->w, pairing);
    element_init_GT(gpk->pr_g1_g2, pairing);
    element_init_GT(gpk->pr_g1_g2_inv, pairing);
    element_init_GT(gpk->pr_h_g2, pairing);
    element_init_GT(gpk->pr_h_w, pairing);

    FILE* stream = fmemopen(pub_key_bytes, pub_key_bytes_len, "r");
    in(gpk->g2, stream);
    in(gpk->g1, stream);
    in(gpk->h, stream);
    in(gpk->u, stream);
    in(gpk->v, stream);
    in(gpk->w, stream);
    in(gpk->pr_g1_g2, stream);
    in(gpk->pr_h_g2, stream);
    in(gpk->pr_h_w, stream);
    in(gpk->pr_g1_g2_inv, stream);
    fclose(stream);
}

void serialize_private_key(bbs_group_private_key_ptr gsk,
    unsigned char* pri_key_bytes, int* pri_key_bytes_len)
{
    size_t size;
    char *bp;
    FILE* stream = open_memstream(&bp, &size);
    out(gsk->A, stream);
    out(gsk->x, stream);
    out(gsk->pr_A_g2, stream);
    fclose(stream);
    (*pri_key_bytes_len) = (int)size;
    memcpy(pri_key_bytes, bp, size);
}

void deserialize_private_key(bbs_group_private_key_ptr gsk,
    unsigned char* pri_key_bytes, int pri_key_bytes_len)
{
    pairing_ptr pairing;
    pairing = gsk->param->pairing;

    element_init_G1(gsk->A, pairing);
    element_init_Zr(gsk->x, pairing);
    element_init_GT(gsk->pr_A_g2, pairing);

    FILE* stream = fmemopen(pri_key_bytes, pri_key_bytes_len, "r");
    in(gsk->A, stream);
    in(gsk->x, stream);
    in(gsk->pr_A_g2, stream);
    fclose(stream);
}

void bbs_sign_raw(
    char* signature, int* sig_length,
    int msg_len, char* msg,
    int pub_key_length, char* pub_key,
    int pri_key_length, char* pri_key)
{

    bbs_sys_param_t sp;
    load_std_params(sp);

    bbs_group_public_key_t s_gpk;
    s_gpk[0].param = sp;

    deserialize_public_key(&s_gpk[0], pub_key, pub_key_length);

    bbs_group_private_key_t s_gsk;
    s_gsk[0].param = sp;
    deserialize_private_key(&s_gsk[0], pri_key, pri_key_length);

    unsigned char *sig;
    sig = (unsigned char *) pbc_malloc(sp->signature_length);

    // sign
    bbs_sign(sig, msg_len, msg, &s_gpk[0], &s_gsk[0]);
    memcpy(signature, sig, sp->signature_length);
    (*sig_length) = sp->signature_length;
}

int bbs_verify_raw(unsigned char *sig,
    int msg_len, void *msg,
    int pub_key_length, unsigned char* pub_key)
{
    bbs_sys_param_t sp;
    load_std_params(sp);

    bbs_group_public_key_t s_gpk;
    s_gpk[0].param = sp;
    
    deserialize_public_key(&s_gpk[0], pub_key, pub_key_length);

    // verify
    return bbs_verify(sig, msg_len, msg, &s_gpk[0]);
}

char* itoa(int val, int base)
{
	static char buf[32] = {0};
	int i = 30;
	for(; val && i ; --i, val /= base)
		buf[i] = "0123456789abcdef"[val % base];
	return &buf[i+1];
}

char* concat(const char *s1, const char *s2)
{
    char *result = malloc(strlen(s1)+strlen(s2)+1);
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}


int main(int argc, char **argv)
{
    int N = 16;
    bbs_sys_param_t sp;
    bbs_group_public_key_t gpk;
    bbs_manager_private_key_t gmsk;
    bbs_group_private_key_t gsk[N];
    pairing_t pairing;
    unsigned char *sig;
    int result;
    element_t A;
    double t0, t1;

    // init pairing
    FILE *curveFile = fopen("d201.param", "r");
    char param_string[16384];
    size_t count = fread(param_string, 1, 16384, curveFile);
    fclose(curveFile);
    pairing_init_set_buf(pairing, param_string, count);

    printf("gen sys param...\n");
    bbs_gen_sys_param(sp, pairing);

    printf("generating keys...\n");
    //t0 = pbc_get_time();
    bbs_gen(gpk, gmsk, N, gsk, sp);
    //t1 = pbc_get_time();
    //printf("%fs elapsed\n", t1 - t0);
    //t0 = t1;

    // Following code was used for serializing the generated keys
/*
    printf("Saving keys to the drive ...\n");
    char pub_key_bytes[4096];
    int pub_key_bytes_len;
    serialize_public_key(gpk, pub_key_bytes, &pub_key_bytes_len);
    printf("Saving public key of length : %d\n", pub_key_bytes_len);
    FILE *file = fopen("admin_keys/admin.pub", "w");
    //int results = fputs(array, file);
    fwrite(pub_key_bytes, 1, pub_key_bytes_len, file);
    fclose(file);


    for(int i=0; i<N; i++)
    {
        char pri_key_bytes[4096];
        int pri_key_bytes_len;
        serialize_private_key(gsk[i], pri_key_bytes, &pri_key_bytes_len);
        printf("Saving private key of length : %d\n", pub_key_bytes_len);

        char* s = itoa(i+1, 10);
        char* dirName = concat("admin_keys/admin", s);

        FILE *f = fopen(dirName, "w");
        //int results = fputs(array, file);
        fwrite(pri_key_bytes, 1, pri_key_bytes_len, f);
        fclose(f);
    }


    return 0;
*/



    printf("sign...\n");
    sig = (unsigned char *) pbc_malloc(sp->signature_length);
    bbs_sign(sig, 0, NULL, gpk, gsk[0]);
    //t1 = pbc_get_time();
    //printf("%fs elapsed\n", t1 - t0);
    //t0 = t1;

    FILE *f = fopen("signature.txt", "w");
    //int results = fputs(array, file);
    fwrite(sig, 1, sp->signature_length, f);
    fclose(f);


    printf("verify...\n");
    result = bbs_verify(sig, 0, NULL, gpk);
    if (result) {
	printf("signature verifies\n");
    } else {
	printf("signature does not verify\n");
    }
    //t1 = pbc_get_time();
    //printf("%fs elapsed\n", t1 - t0);
    //t0 = t1;
    element_init_G1(A, pairing);
    bbs_open(A, gpk, gmsk, 0, NULL, sig);
    element_printf("open A = %B\n", A);
    element_printf("gsk0 A = %B\n", gsk[0]->A);
    //t1 = pbc_get_time();
    //printf("%fs elapsed\n", t1 - t0);
    //t0 = t1;

    return 0;
}

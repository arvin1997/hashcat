/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "locking.h"
#include "emu_inc_rp.h"
#include "emu_inc_rp_optimized.h"
#include "mpsp.h"
#include "backend.h"
#include "shared.h"
#include "stdout.h"

static void out_flush (out_t *out)
{
  if (out->len == 0) return;

  hc_fwrite (out->buf, 1, out->len, &out->fp);

  out->len = 0;
}

static void out_push (out_t *out, const u8 *pw_buf, const int pw_len)
{
  char *ptr = out->buf + out->len;

  memcpy (ptr, pw_buf, pw_len);

  #if defined (_WIN)

  ptr[pw_len + 0] = '\r';
  ptr[pw_len + 1] = '\n';

  out->len += pw_len + 2;

  #else

  ptr[pw_len] = '\n';

  out->len += pw_len + 1;

  #endif

  if (out->len >= HCBUFSIZ_SMALL - 300)
  {
    out_flush (out);
  }
}

int process_stdout (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt)
{
  combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
  hashconfig_t     *hashconfig     = hashcat_ctx->hashconfig;
  mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
  outfile_ctx_t    *outfile_ctx    = hashcat_ctx->outfile_ctx;
  straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;
  user_options_t   *user_options   = hashcat_ctx->user_options;

  char *filename = outfile_ctx->filename;

  out_t out;

  if (filename)
  {
    if (hc_fopen (&out.fp, filename, "ab") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", filename, strerror (errno));

      return -1;
    }

    if (hc_lockfile (&out.fp) == -1)
    {
      hc_fclose (&out.fp);

      event_log_error (hashcat_ctx, "%s: %s", filename, strerror (errno));

      return -1;
    }
  }
  else
  {
    out.fp.is_gzip = false;
    out.fp.pfp = stdout;
    out.fp.fd = fileno (stdout);
  }

  out.len = 0;

  u32 plain_buf[64] = { 0 };

  u8 *plain_ptr = (u8 *) plain_buf;

  u32 plain_len = 0;

  const u32 il_cnt = device_param->kernel_params_buf32[30]; // ugly, i know

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    pw_t pw;
    

    printf("stdout.c  外循环开始 pws_cnt=%d\n",pws_cnt);
    for (u64 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1)
      {
        if (filename) hc_fclose (&out.fp);

        return -1;
      }

      printf("stdout.c  内循环开始 il_cnt=%d\n",il_cnt); //等于rule条数
      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        const u32 off = device_param->innerloop_pos + il_pos; //第几条rule

        if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
        {
          for (int i = 0; i < 8; i++)
          {
            plain_buf[i] = pw.i[i];
          }
          printf("调用 apply_rules_optimized\n");

          plain_len = apply_rules_optimized (straight_ctx->kernel_rules_buf[off].cmds, &plain_buf[0], &plain_buf[4], pw.pw_len);
        }
        else
        {
          //尝试输入更大的plain_buf并在受语义规则处理后变成特殊结构
          u32 plain_buf_plus[300*(65)]={0}; //+++++++++++++

          for (int i = 0; i < 64; i++)
          {
            //plain_buf[i] = pw.i[i];  //u32 i[64];  uchar-u8 uint-u32 64*4=256位
            plain_buf_plus[i] = pw.i[i];
          }
          printf("调用 apply_rules\n 每条rule：\n"); //调用了 apply_rules 而非 apply_rules_optimized
          //printf("%s\n",straight_ctx->kernel_rules_buf[off].cmds,straight_ctx->kernel_rules_buf[off].cmds[0],straight_ctx->kernel_rules_buf[off].cmds[1],straight_ctx->kernel_rules_buf[off].cmds[2]);
          //printf("%x %x %x\n",);
          u8 name;
          for (u32 i1 = 0; straight_ctx->kernel_rules_buf[off].cmds[i1] != 0; i1++)
            {
              const u32 cmd = straight_ctx->kernel_rules_buf[off].cmds[i1];
              //printf("%x ",cmd);
              //name = (cmd >>  0) & 0xff;
              //const u8 p0   = (cmd >>  8) & 0xff;
              //const u8 p1   = (cmd >> 16) & 0xff;
              //const u9 p2= (cmd >> 24) & 0xff; //可不可以加？？？？
              //printf("[%c %c %c] ",name,p0,p1);
              // we need to guarantee input length < 256 otherwise functions like rule_op_mangle_switch_last() and others will read out of boundary
            }
          
          //printf("\n");
          //搞清楚格式：1.直接打印(已知kernel_rules_buf的类型是*kernel_rule_t，即指向{u32 cmds[32]}) 
          //2.结合rp.c中的cpu_rule_to_kernel_rule
          
          plain_len = apply_rules (straight_ctx->kernel_rules_buf[off].cmds, plain_buf_plus, pw.pw_len);
        }

        if(plain_len<0){
          int 
        }

        if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    pw_t pw;

    for (u64 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1)
      {
        if (filename) hc_fclose (&out.fp);

        return -1;
      }

      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 64; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        plain_len = pw.pw_len;

        char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
        u32   comb_len =          device_param->combs_buf[il_pos].pw_len;

        if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
        {
          memcpy (plain_ptr + plain_len, comb_buf, comb_len);
        }
        else
        {
          memmove (plain_ptr + comb_len, plain_ptr, plain_len);

          memcpy (plain_ptr, comb_buf, comb_len);
        }

        plain_len += comb_len;

        if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    for (u64 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        u64 l_off = device_param->kernel_params_mp_l_buf64[3] + gidvid;
        u64 r_off = device_param->kernel_params_mp_r_buf64[3] + il_pos;

        u32 l_start = device_param->kernel_params_mp_l_buf32[5];
        u32 r_start = device_param->kernel_params_mp_r_buf32[5];

        u32 l_stop = device_param->kernel_params_mp_l_buf32[4];
        u32 r_stop = device_param->kernel_params_mp_r_buf32[4];

        sp_exec (l_off, (char *) plain_ptr + l_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, l_start, l_start + l_stop);
        sp_exec (r_off, (char *) plain_ptr + r_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, r_start, r_start + r_stop);

        plain_len = mask_ctx->css_cnt;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    pw_t pw;

    for (u64 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1)
      {
        if (filename) hc_fclose (&out.fp);

        return -1;
      }

      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 64; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        plain_len = pw.pw_len;

        u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

        u32 start = 0;
        u32 stop  = device_param->kernel_params_mp_buf32[4];

        sp_exec (off, (char *) plain_ptr + plain_len, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

        plain_len += start + stop;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    pw_t pw;

    for (u64 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1)
      {
        if (filename) hc_fclose (&out.fp);

        return -1;
      }

      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        u64 off = device_param->kernel_params_mp_buf64[3] + gidvid;

        u32 start = 0;
        u32 stop  = device_param->kernel_params_mp_buf32[4];

        sp_exec (off, (char *) plain_ptr, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

        plain_len = stop;

        char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
        u32   comb_len =          device_param->combs_buf[il_pos].pw_len;

        memcpy (plain_ptr + plain_len, comb_buf, comb_len);

        plain_len += comb_len;

        if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }

  out_flush (&out);

  if (filename) hc_fclose (&out.fp);

  return 0;
}

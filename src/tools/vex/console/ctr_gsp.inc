/* gsp::Gpu, the 3DS's graphics service (after console/ctr.inc and console/frames.inc): what a title needs to show
 * its frames. Formats from libctru's GSPGPU client (gspgpu.c, gx.c), the reference for how titles talk to it.
 *
 * - Rights and the interrupt queue: AcquireRight, RegisterInterruptRelayQueue (the event the service signals, and
 *   its shared memory block: the interrupt queue at 0x40 * thread, framebuffer info at 0x200 + 0x80 * thread +
 *   0x40 * screen, the GX command queue at 0x800 + 0x200 * thread). One client: thread 0.
 * - The vertical blank, 60 times a second: a framebuffer presented since the last one (through the shared memory's
 *   framebuffer info, or SetBufferSwap) is shown, and written out as a frame (frames.inc); then VBlank0 and
 *   VBlank1 are pushed on the interrupt queue and the event signalled.
 * - GX commands (TriggerCmdReqQueue): a DMA copy and a memory fill are carried out; the display transfer, texture
 *   copy and command list (the GPU's work, PICA200) are not yet, and are logged as unserved, but their completion
 *   interrupt is still raised so that a title waiting on it goes on (its frame then shows what was not drawn).
 * - Hardware registers are accepted and not modelled (reads give 0); cache operations have nothing to do. */

#define CTR_GSP_PERIOD 16715000u /* ns between vertical blanks: the 3DS's 59.83 Hz */
enum { CTR_GSP_PSC0, CTR_GSP_PSC1, CTR_GSP_VBLANK0, CTR_GSP_VBLANK1, CTR_GSP_PPF, CTR_GSP_P3D, CTR_GSP_DMA };

static uint8_t *ctr_gsp_mem;           /* the guest memory */
static uint32_t ctr_gsp_event;         /* the client's event handle, 0 before it registers */
static uint32_t ctr_gsp_shared;        /* the shared memory block's handle */
struct ctr_gsp_screen { uint32_t address, stride, format; unsigned shown; };
static struct ctr_gsp_screen ctr_gsp_screens[2];

static uint32_t ctr_gsp_shared_address(void) {
  struct console_object *o = console_handle_get(ctr_gsp_shared);
  return o != NULL ? (uint32_t)o->value : 0;
}

/* Pushes an interrupt on the client's queue (0x34 entries after a 0xC-byte header: current, count, error). */
static void ctr_gsp_interrupt(int id) {
  uint32_t base = ctr_gsp_shared_address();
  if (base == 0) return;
  uint8_t *queue = ctr_gsp_mem + base;
  if (queue[1] >= 0x34) {
    queue[2] = 1;
  } else {
    queue[0xC + (queue[0] + queue[1]) % 0x34] = (uint8_t)id;
    queue[1]++;
  }
  struct console_object *event = console_handle_get(ctr_gsp_event);
  if (event != NULL && event->kind == CONSOLE_EVENT) event->count = 1;
}

/* One pixel of a framebuffer in the given format, as RGB (formats from libctru: GSPGPU_FramebufferFormat). */
static void ctr_gsp_pixel(const uint8_t *p, uint32_t format, uint8_t *rgb) {
  uint16_t v = (uint16_t)(p[0] | p[1] << 8);
  switch (format & 7) {
    case 0: rgb[0] = p[3]; rgb[1] = p[2]; rgb[2] = p[1]; break; /* RGBA8: A, B, G, R in memory */
    case 1: rgb[0] = p[2]; rgb[1] = p[1]; rgb[2] = p[0]; break; /* BGR8: B, G, R in memory */
    case 2: rgb[0] = (uint8_t)((v >> 11) * 255 / 31); rgb[1] = (uint8_t)((v >> 5 & 63) * 255 / 63);
            rgb[2] = (uint8_t)((v & 31) * 255 / 31); break; /* RGB565 */
    case 3: rgb[0] = (uint8_t)((v >> 11) * 255 / 31); rgb[1] = (uint8_t)((v >> 6 & 31) * 255 / 31);
            rgb[2] = (uint8_t)((v >> 1 & 31) * 255 / 31); break; /* RGB5A1 */
    default: rgb[0] = (uint8_t)((v >> 12) * 17); rgb[1] = (uint8_t)((v >> 8 & 15) * 17);
             rgb[2] = (uint8_t)((v >> 4 & 15) * 17); break; /* RGBA4 */
  }
}

static unsigned ctr_gsp_bytes(uint32_t format) {
  switch (format & 7) { case 0: return 4; case 1: return 3; default: return 2; }
}

/* Shows a screen's framebuffer: the panels are mounted rotated, so the framebuffer holds the image column by
 * column, 240 pixels each from the bottom up (the top screen 400 columns, the bottom one 320). */
static void ctr_gsp_show(int screen) {
  struct ctr_gsp_screen *sc = &ctr_gsp_screens[screen];
  unsigned width = screen == 0 ? 400 : 320, height = 240, bytes = ctr_gsp_bytes(sc->format);
  uint32_t stride = sc->stride ? sc->stride : height * bytes;
  uint8_t *rgb = malloc((size_t)width * height * 3);
  if (rgb == NULL) return;
  for (unsigned x = 0; x < width; x++)
    for (unsigned y = 0; y < height; y++)
      ctr_gsp_pixel(ctr_gsp_mem + sc->address + x * stride + (height - 1 - y) * bytes, sc->format,
                    rgb + ((size_t)y * width + x) * 3);
  console_frame_write(screen == 0 ? "top" : "bottom", ++sc->shown, width, height, rgb);
  free(rgb);
}

/* A framebuffer info (libctru's GSPGPU_FramebufferInfo: active, address 0, address 1, stride, format, ...). */
static void ctr_gsp_present(int screen, const uint32_t *info) {
  struct ctr_gsp_screen *sc = &ctr_gsp_screens[screen];
  sc->address = info[0] ? info[2] : info[1];
  sc->stride = info[3];
  sc->format = info[4];
  ctr_gsp_show(screen);
}

static void ctr_gsp_vblank(void) {
  uint32_t base = ctr_gsp_shared_address();
  for (int screen = 0; base != 0 && screen < 2; screen++) {
    uint32_t *header = (uint32_t *)(ctr_gsp_mem + base + 0x200 + 0x40 * screen);
    if ((*header & 0xFF00) == 0) continue; /* nothing new presented */
    ctr_gsp_present(screen, header + 1 + 7 * (*header & 1));
    *header &= ~0xFF00u;
  }
  ctr_gsp_interrupt(CTR_GSP_VBLANK0);
  ctr_gsp_interrupt(CTR_GSP_VBLANK1);
}

/* Carries out the GX commands queued in shared memory (15 slots of 8 words after a header: index, count). */
static void ctr_gsp_commands(void) {
  uint32_t base = ctr_gsp_shared_address();
  if (base == 0) return;
  uint32_t *queue = (uint32_t *)(ctr_gsp_mem + base + 0x800);
  while ((*queue >> 8 & 0xFF) != 0) {
    uint32_t index = *queue & 0xFF, *c = queue + 8 * (1 + index);
    switch (c[0] & 0xFF) {
      case 0: /* DMA: source, destination, size */
        memmove(ctr_gsp_mem + c[2], ctr_gsp_mem + c[1], c[3]);
        ctr_gsp_interrupt(CTR_GSP_DMA);
        break;
      case 2: /* memory fill: two buffers (start, value, end), each with its control (bit 0 start, 8-9 width) */
        for (int k = 0; k < 2; k++) {
          uint32_t start = c[1 + 3 * k], value = c[2 + 3 * k], end = c[3 + 3 * k];
          uint32_t control = k == 0 ? c[7] & 0xFFFF : c[7] >> 16;
          if (start == 0 || !(control & 1)) continue;
          unsigned width = (control >> 8 & 3) == 0 ? 2 : (control >> 8 & 3) == 1 ? 3 : 4;
          for (uint32_t a = start; a + width <= end; a += width) memcpy(ctr_gsp_mem + a, &value, width);
          ctr_gsp_interrupt(k == 0 ? CTR_GSP_PSC0 : CTR_GSP_PSC1);
        }
        break;
      case 1: console_unserved("gsp GX command", 1); ctr_gsp_interrupt(CTR_GSP_P3D); break; /* command list */
      case 3: case 4: console_unserved("gsp GX command", c[0] & 0xFF); ctr_gsp_interrupt(CTR_GSP_PPF); break;
      case 5: break; /* cache flush: nothing to do */
      default: console_unserved("gsp GX command", c[0] & 0xFF);
    }
    *queue = (*queue & 0xFFFF0000u) | (((*queue >> 8 & 0xFF) - 1) << 8) | ((index + 1) % 15);
  }
}

static void ctr_gsp(atlas_state *s, uint8_t *command, struct console_object *session) {
  (void)session;
  uint32_t *c = (uint32_t *)command, id = c[0] >> 16;
  switch (id) {
    case 0x01: case 0x02: case 0x0B: case 0x08: case 0x09: case 0x14: case 0x16: case 0x17: break;
    case 0x04: /* ReadHWRegs(address, size): into the static buffer the request names */
      memset(ctr_gsp_mem + c[0x41], 0, c[2]);
      break;
    case 0x05: /* SetBufferSwap(screen, info) */
      if (c[1] < 2) ctr_gsp_present((int)c[1], c + 2);
      break;
    case 0x0C: ctr_gsp_commands(); break; /* TriggerCmdReqQueue */
    case 0x13: { /* RegisterInterruptRelayQueue(flags, event): out thread 0 and the shared memory block */
      ctr_gsp_mem = s->mem;
      ctr_gsp_event = c[3];
      if (ctr_gsp_shared == 0) ctr_gsp_shared = console_handle_new(CONSOLE_MEMORY, 0, NULL);
      if (console_tick == NULL) console_every(CTR_GSP_PERIOD, ctr_gsp_vblank);
      c[0] = 0x00130042;
      c[1] = 0x2A07; /* the first client: libctru then initialises the hardware */
      c[2] = 0;      /* the client's thread index */
      c[3] = 0x10;   /* one handle moved */
      c[4] = ctr_gsp_shared;
      return;
    }
    default:
      console_unserved("gsp::Gpu", id);
      c[0] = (id << 16) | 0x40;
      c[1] = CTR_NOT_IMPLEMENTED;
      return;
  }
  c[0] = (id << 16) | 0x40; /* the result alone */
  c[1] = CTR_OK;
}

/* The frames a guest shows, written for comparison (docs/ROADMAP.md, "Comparing images"). No console in it: a
 * profile decodes its framebuffers into rows of RGB and hands them here. With ATLAS_FRAMES=<directory>, each frame
 * shown is written there as <screen>-<number>.ppm (binary PPM, numbered from 1 per screen in the order shown, so two
 * runs of the same title name the same frame alike); without it, nothing is written. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void console_frame_write(const char *screen, unsigned number, unsigned width, unsigned height,
                                const uint8_t *rgb) {
  const char *directory = getenv("ATLAS_FRAMES");
  if (directory == NULL) return;
  char path[4096];
  snprintf(path, sizeof path, "%s/%s-%04u.ppm", directory, screen, number);
  FILE *out = fopen(path, "wb");
  if (out == NULL) {
    fprintf(stderr, "atlas: cannot write the frame %s\n", path);
    return;
  }
  fprintf(out, "P6\n%u %u\n255\n", width, height);
  fwrite(rgb, 3, (size_t)width * height, out);
  fclose(out);
}

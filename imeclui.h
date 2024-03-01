#ifndef IMECLUI_H__
#define IMECLUI_H__

#ifdef _WIN32

#ifdef ADD_EXPORTS
#define ADDAPI __declspec(dllexport)
#else // ADD_EXPORTS
#define ADDAPI __declspec(dllimport)
#endif // ADD_EXPORTS

#define ADDCALL __cdecl

#else // _WIN32
#define ADDAPI
#define ADDCALL
#endif // _WIN32

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else // _WIN32
#include <sys/ioctl.h>
#include <termios.h>
#endif // _WIN32

#define IME_ESC "\x1B["
#define IME_ESC_END "m"

#define IME_RESET "0"
#define IME_BOLD "1"
#define IME_DIM "2"
#define IME_ITALIC "3"
#define IME_UNDERLINE "4"
#define IME_BLINK "5"
#define IME_INVERTED "7"
#define IME_HIDDEN "8"
#define IME_STRIKETHROUGH "9"

#define IME_NOT_BOLD "21"
#define IME_NOT_DIM "22"
#define IME_NOT_ITALIC "23"
#define IME_NOT_UNDERLINE "24"
#define IME_NOT_BLINK "25"
#define IME_NOT_INVERTED "27"
#define IME_NOT_HIDDEN "28"
#define IME_NOT_STRIKETHROUGH "29"

#define IME_BLACK "30"
#define IME_RED "31"
#define IME_GREEN "32"
#define IME_YELLOW "33"
#define IME_BLUE "34"
#define IME_MAGENTA "35"
#define IME_CYAN "36"
#define IME_WHITE "37"
#define IME_NORMAL "39"

    // #define IME_BRIGHT_BLACK "1;30"
    // #define IME_BRIGHT_RED "1;31"
    // #define IME_BRIGHT_GREEN "1;32"
    // #define IME_BRIGHT_YELLOW "1;33"
    // #define IME_BRIGHT_BLUE "1;34"
    // #define IME_BRIGHT_MAGENTA "1;35"
    // #define IME_BRIGHT_CYAN "1;36"
    // #define IME_BRIGHT_WHITE "1;37"

#define IME_BRIGHT_BLACK "90"
#define IME_BRIGHT_RED "91"
#define IME_BRIGHT_GREEN "92"
#define IME_BRIGHT_YELLOW "93"
#define IME_BRIGHT_BLUE "94"
#define IME_BRIGHT_MAGENTA "95"
#define IME_BRIGHT_CYAN "96"
#define IME_BRIGHT_WHITE "97"

#define IME_BG_BLACK "40"
#define IME_BG_RED "41"
#define IME_BG_GREEN "42"
#define IME_BG_YELLOW "43"
#define IME_BG_BLUE "44"
#define IME_BG_MAGENTA "45"
#define IME_BG_CYAN "46"
#define IME_BG_WHITE "47"
#define IME_BG_NORMAL "49"

#define IME_BG_BRIGHT_BLACK "100"
#define IME_BG_BRIGHT_RED "101"
#define IME_BG_BRIGHT_GREEN "102"
#define IME_BG_BRIGHT_YELLOW "103"
#define IME_BG_BRIGHT_BLUE "104"
#define IME_BG_BRIGHT_MAGENTA "105"
#define IME_BG_BRIGHT_CYAN "106"
#define IME_BG_BRIGHT_WHITE "107"

#define IME_256_COLOR(C) "38;5;" #C
#define IME_BG_256_COLOR(C) "48;5;" #C

#define IME_RGB_COLOR(R, G, B) "38;2;" #R ";" #G ";" #B
#define IME_BG_RGB_COLOR(R, G, B) "48;2;" #R ";" #G ";" #B

#define IME_STYLE_BOLD 0b00000001
#define IME_STYLE_DIM 0b00000010
#define IME_STYLE_ITALIC 0b00000100
#define IME_STYLE_UNDERLINE 0b00001000
#define IME_STYLE_BLINK 0b00010000
#define IME_STYLE_INVERTED 0b00100000
#define IME_STYLE_HIDDEN 0b01000000
#define IME_STYLE_STRIKETHROUGH 0b10000000

#define __IME_COLOR_STR_BUFFER_SIZE 16
#define __IME_STYLE_STR_BUFFER_SIZE 128

#define ime_clear_screen() write(1, "\033[H\033[2J\033[3J", 11)
#define ime_move_cursor(X, Y) printf("\033[%d;%dH", (Y), (X))
#define ime_enter_alt_screen() puts("\033[?1049h\033[H")
#define ime_exit_alt_screen() puts("\033[?1049l")

    /* HEADER START --> */

    typedef struct Cell
    {
        char symbol;
        char *fg_color;
        char *bg_color;
        short style;
    } Cell;

    typedef struct CellBuffer
    {
        Cell **cells;
        int cols;
        int rows;
        int size;
    } CellBuffer;

    ADDAPI int ADDCALL ime_lib_ping();

    ADDAPI void ADDCALL ime_get_tsize(int *cols, int *rows);

    ADDAPI void ADDCALL ime_echo_off();
    ADDAPI void ADDCALL ime_echo_on();

    ADDAPI void ADDCALL ime_fill_screen(char *color);
    ADDAPI void ADDCALL ime_fill_rect(Cell *cell, size_t lu_x, size_t lu_y,
                                      size_t rb_x, size_t rb_y);

    ADDAPI Cell ADDCALL *ime_alloc_cell(char symbol, const char *fg_color,
                                        const char *bg_color, short style);
    ADDAPI void ADDCALL ime_free_cell(Cell *cell);
    ADDAPI void ADDCALL __ime_log_cell(Cell *cell);

    ADDAPI void ADDCALL ime_alloc_cells_linear(CellBuffer *buffer, int size);
    ADDAPI CellBuffer ADDCALL *ime_alloc_cells(int cols, int rows);
    ADDAPI void ADDCALL ime_free_cells(CellBuffer *buffer);
    ADDAPI void ADDCALL __ime_log_cells(CellBuffer *buffer);

    ADDAPI char ADDCALL *ime_style_builder(char *fg_color, char *bg_color,
                                           short cfg);

    ADDAPI char ADDCALL *__ime_get_escape_string(char *str);

    ADDAPI void ADDCALL ime_draw_cell(Cell *cell, size_t x, size_t y);

    ADDAPI bool ADDCALL ime_is_stdin_tty();
    ADDAPI bool ADDCALL ime_is_stdout_tty();

    ADDAPI void ADDCALL ime_copy_cell(Cell *dst, Cell *src);

    ADDAPI void ADDCALL ime_place_buffer(CellBuffer *buf);

    ADDAPI void ADDCALL ime_b_fill_rect(CellBuffer *buf, Cell *cell,
                                        size_t lu_x, size_t lu_y,
                                        size_t rb_x, size_t rb_y);
    ADDAPI void ADDCALL ime_draw_frame(CellBuffer *buf,
                                       size_t lu_x, size_t lu_y,
                                       size_t rb_x, size_t rb_y);
    ADDAPI void ADDCALL ime_draw_frame_double(CellBuffer *buf,
                                              size_t lu_x, size_t lu_y,
                                              size_t rb_x, size_t rb_y);
    ADDAPI void ADDCALL ime_draw_line(CellBuffer *buf,
                                      size_t lu_x, size_t lu_y,
                                      size_t rb_x, size_t rb_y);
    ADDAPI void ADDCALL ime_bell();

#ifdef IMECLUI_IMPLEMENTATION

    /* IMPLEMENTATION START --> */

    ADDAPI int ADDCALL
    ime_lib_ping()
    {
        printf("Pong from imeclui!\n");
        return 0;
    }

    ADDAPI void ADDCALL ime_get_tsize(int *cols, int *rows)
    {
#ifdef _WIN32
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        *cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        *rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
#else  // _WIN32
        struct winsize w;
        ioctl(0, TIOCGWINSZ, &w);
        *cols = w.ws_col;
        *rows = w.ws_row;
#endif // _WIN32
    }

    ADDAPI void ADDCALL ime_echo_off()
    {
#ifdef _WIN32
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hStdin, &mode);
        SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
#else  // _WIN32
       // struct termios term;
       // tcgetattr(0, &term);
       // term.c_lflag &= ~ECHO;
       // tcsetattr(0, TCSANOW, &term);
#endif // _WIN32
    }

    ADDAPI void ADDCALL ime_echo_on()
    {
#ifdef _WIN32
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hStdin, &mode);
        SetConsoleMode(hStdin, mode | ENABLE_ECHO_INPUT);
#else  // _WIN32
       // struct termios term;
       // tcgetattr(0, &term);
       // term.c_lflag |= ECHO;
       // tcsetattr(0, TCSANOW, &term);
#endif // _WIN32
    }

    ADDAPI Cell ADDCALL *ime_alloc_cell(char symbol, const char *fg_color, const char *bg_color, short style)
    {
        Cell *cell = (Cell *)malloc(sizeof(Cell));
        cell->fg_color = (char *)malloc(__IME_COLOR_STR_BUFFER_SIZE);
        cell->bg_color = (char *)malloc(__IME_COLOR_STR_BUFFER_SIZE);
        cell->symbol = symbol;
        cell->style = style;
        sprintf(cell->fg_color, "%s", fg_color);
        sprintf(cell->bg_color, "%s", bg_color);
        return cell;
    }

    ADDAPI void ADDCALL ime_free_cell(Cell *cell)
    {
        free(cell->fg_color);
        free(cell->bg_color);
        free(cell);
    }

    ADDAPI char ADDCALL *__ime_get_escape_string(char *str)
    {
        // if any non-ascii character is found, replace it with hex escape sequence
        char *buf = (char *)malloc(__IME_STYLE_STR_BUFFER_SIZE);
        for (int i = 0; i < __IME_STYLE_STR_BUFFER_SIZE; i++)
        {
            buf[i] = '\0';
        }
        char *p = buf;
        while (*str != '\0')
        {
            if (*str < 0x20 || *str > 0x7e)
            {
                p += sprintf(p, "\\x%02X", (*str) & 0xff);
            }
            else
            {
                p += sprintf(p, "%c", *str);
            }
            str++;
        }
        *p = '\0';
        return buf;
    }

    ADDAPI void ADDCALL __ime_log_cell(Cell *cell)
    {
        char *fg_color = __ime_get_escape_string(cell->fg_color);
        char *bg_color = __ime_get_escape_string(cell->bg_color);
        printf("{char: %c, fg_color: %s, bg_color: %s, style: 0x%X}\n", cell->symbol, fg_color, bg_color, cell->style);
        free(fg_color);
        free(bg_color);
    }

    ADDAPI void ADDCALL __ime_log_cells(CellBuffer *buffer)
    {
        for (int i = 0; i < buffer->size; i++)
        {
            printf("%04d: ", i);
            __ime_log_cell(buffer->cells[i]);
        }
    }

    ADDAPI char ADDCALL *ime_style_builder(char *fg_color, char *bg_color, short cfg)
    {
        // TODO: use a buffer instead of malloc
        // TODO: or count precizely max length of the string
        char *style = (char *)malloc(__IME_STYLE_STR_BUFFER_SIZE);
        for (int i = 0; i < __IME_STYLE_STR_BUFFER_SIZE; i++)
            style[i] = '\0';
        strcat(style, IME_ESC ";");
        strcat(style, fg_color);
        strcat(style, ";");
        strcat(style, bg_color);
        strcat(style, ";");
        if (cfg & IME_STYLE_BOLD)
            strcat(style, IME_BOLD ";");
        else
            strcat(style, IME_NOT_BOLD ";");
        if (cfg & IME_STYLE_DIM)
            strcat(style, IME_DIM ";");
        else
            strcat(style, IME_NOT_DIM ";");
        if (cfg & IME_STYLE_ITALIC)
            strcat(style, IME_ITALIC ";");
        else
            strcat(style, IME_NOT_ITALIC ";");
        if (cfg & IME_STYLE_UNDERLINE)
            strcat(style, IME_UNDERLINE ";");
        else
            strcat(style, IME_NOT_UNDERLINE ";");
        if (cfg & IME_STYLE_BLINK)
            strcat(style, IME_BLINK ";");
        else
            strcat(style, IME_NOT_BLINK ";");
        if (cfg & IME_STYLE_INVERTED)
            strcat(style, IME_INVERTED ";");
        else
            strcat(style, IME_NOT_INVERTED ";");
        if (cfg & IME_STYLE_HIDDEN)
            strcat(style, IME_HIDDEN ";");
        else
            strcat(style, IME_NOT_HIDDEN ";");
        if (cfg & IME_STYLE_STRIKETHROUGH)
            strcat(style, IME_STRIKETHROUGH);
        else
            strcat(style, IME_NOT_STRIKETHROUGH);
        strcat(style, IME_ESC_END);
        return style;
    }

    ADDAPI bool ADDCALL ime_is_stdin_tty()
    {
        return (isatty(fileno(stdin))
                    ? "stdin is tty"
                    : "stdin is not tty");
    }

    ADDAPI bool ADDCALL ime_is_stdout_tty()
    {
        return (isatty(fileno(stdout))
                    ? "stdout is tty"
                    : "stdout is not tty");
    }

    // ADDAPI void ADDCALL ime_alloc_cells_linear(CellBuffer *buffer, int size)
    // {
    //     buffer->cells = malloc(size * sizeof(Cell));
    //     buffer->size = size;
    //     buffer->cols = -1;
    //     buffer->rows = -1;
    //     for (int i = 0; i < size; i++)
    //     {
    //         ime_alloc_cell(&buffer->cells[i]);
    //     }
    // }

    ADDAPI CellBuffer ADDCALL *ime_alloc_cells(int cols, int rows)
    {
        CellBuffer *buffer = (CellBuffer *)malloc(sizeof(CellBuffer));
        buffer->cells = (Cell **)malloc(cols * rows * sizeof(Cell));
        buffer->cols = cols;
        buffer->rows = rows;
        buffer->size = cols * rows;
        for (int i = 0; i < buffer->size; i++)
        {
            buffer->cells[i] = ime_alloc_cell(' ', IME_NORMAL, IME_BG_NORMAL, 0);
        }
        return buffer;
    }

    ADDAPI void ADDCALL ime_free_cells(CellBuffer *buffer)
    {
        for (int i = 0; i < buffer->size; i++)
        {
            ime_free_cell(buffer->cells[i]);
        }
        free(buffer->cells);
        free(buffer);
    }

    ADDAPI void ADDCALL ime_fill_screen(char *color)
    {
        int cols, rows;
        ime_get_tsize(&cols, &rows);
        char *buffer = (char *)malloc(cols * rows + 1);
        for (int i = 0; i < rows; i++)
        {
            for (int j = 0; j < cols; j++)
            {
                buffer[i * cols + j] = ' ';
            }
        }
        buffer[cols * rows] = '\0';
        printf(color);
        printf(buffer);
        free(buffer);
    }

    ADDAPI void ADDCALL ime_draw_cell(Cell *cell, size_t x, size_t y)
    {
        ime_move_cursor(x, y);
        char *style = ime_style_builder(cell->fg_color, cell->bg_color, cell->style);
        printf(style);
        printf("%c", cell->symbol);
        free(style);
    }

    ADDAPI void ADDCALL ime_fill_rect(Cell *cell, size_t lu_x, size_t lu_y,
                                      size_t rb_x, size_t rb_y)
    {
        ime_move_cursor(lu_x, lu_y);
        size_t width = rb_x - lu_x;
        size_t height = rb_y - lu_y;
        for (unsigned y = 0; y < height; y++)
        {
            for (unsigned x = 0; x < width; x++)
            {
                size_t curr_x = lu_x + x;
                size_t curr_y = lu_y + y;
                ime_draw_cell(cell, curr_x, curr_y);
            }
        }
    }

    ADDAPI void ADDCALL __ime_slow_place_buffer(CellBuffer *buf)
    {
        for (int i = 0; i < buf->rows; i++)
        {
            for (int j = 0; j < buf->cols; j++)
            {
                ime_draw_cell(buf->cells[i], j, i);
            }
        }
    }

    ADDAPI void ADDCALL ime_place_buffer(CellBuffer *buf)
    {
        char *screen = (char *)calloc(buf->size * 64, 1);
        size_t printed = 0;
        size_t t;
        for (int i = 0; i < buf->rows; i++)
        {
            for (int j = 0; j < buf->cols; j++)
            {
                t = sprintf(screen, ime_style_builder(
                                        buf->cells[j * buf->rows + i]->fg_color,
                                        buf->cells[j * buf->rows + i]->bg_color,
                                        buf->cells[j * buf->rows + i]->style));
                printed += t;
                screen += t;
                t = sprintf(screen, "%c",
                            buf->cells[j * buf->rows + i]->symbol);
                printed += t;
                screen += t;
            }
        }
        ime_clear_screen();
        screen -= printed;
        printf(screen);
        free(screen);
    }

    ADDAPI void ADDCALL ime_copy_cell(Cell *dst, Cell *src)
    {
        dst->symbol = src->symbol;
        dst->style = src->style;
        strcpy(dst->fg_color, src->fg_color);
        strcpy(dst->bg_color, src->bg_color);
    }

    ADDAPI void ADDCALL ime_b_fill_rect(CellBuffer *buf, Cell *cell,
                                        size_t lu_x, size_t lu_y,
                                        size_t rb_x, size_t rb_y)
    {
        size_t width = rb_x - lu_x;
        size_t height = rb_y - lu_y;
        for (unsigned y = 0; y < height; y++)
        {
            for (unsigned x = 0; x < width; x++)
            {
                size_t curr_x = lu_x + x;
                size_t curr_y = lu_y + y;
                ime_copy_cell(buf->cells[curr_x * buf->rows + curr_y], cell);
            }
        }
    }

    ADDAPI void ADDCALL ime_draw_frame(CellBuffer *buf,
                                       size_t lu_x, size_t lu_y,
                                       size_t rb_x, size_t rb_y)
    {
        char vertical = 0xB3;
        char horizontal = 0xC4;
        char left_up = 0xDA;
        char left_down = 0xC0;
        char right_down = 0xD9;
        char right_up = 0xBF;
        size_t width = rb_x - lu_x;
        size_t height = rb_y - lu_y;
        for (unsigned y = 0; y < height; y++)
        {
            for (unsigned x = 0; x < width; x++)
            {
                size_t curr_x = lu_x + x;
                size_t curr_y = lu_y + y;
                if (x == 0 && y == 0)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = left_up;
                }
                else if (x == 0 && y == height - 1)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = left_down;
                }
                else if (x == width - 1 && y == 0)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = right_up;
                }
                else if (x == width - 1 && y == height - 1)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = right_down;
                }
                else if (x == 0 || x == width - 1)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = vertical;
                }
                else if (y == 0 || y == height - 1)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = horizontal;
                }
            }
        }
    }

    ADDAPI void ADDCALL ime_draw_frame_double(CellBuffer *buf,
                                              size_t lu_x, size_t lu_y,
                                              size_t rb_x, size_t rb_y)
    {
        char vertical = 0xBA;
        char horizontal = 0xCD;
        char left_up = 0xC9;
        char left_down = 0xC8;
        char right_down = 0xBC;
        char right_up = 0xBB;
        size_t width = rb_x - lu_x;
        size_t height = rb_y - lu_y;
        for (unsigned y = 0; y < height; y++)
        {
            for (unsigned x = 0; x < width; x++)
            {
                size_t curr_x = lu_x + x;
                size_t curr_y = lu_y + y;
                if (x == 0 && y == 0)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = left_up;
                }
                else if (x == 0 && y == height - 1)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = left_down;
                }
                else if (x == width - 1 && y == 0)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = right_up;
                }
                else if (x == width - 1 && y == height - 1)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = right_down;
                }
                else if (x == 0 || x == width - 1)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = vertical;
                }
                else if (y == 0 || y == height - 1)
                {
                    buf->cells[curr_x * buf->rows + curr_y]->symbol = horizontal;
                }
            }
        }
    }

    ADDAPI void ADDCALL ime_bell()
    {
        printf("\a");
    }

    ADDAPI void ADDCALL ime_draw_line(CellBuffer *buf,
                                      size_t lu_x, size_t lu_y,
                                      size_t rb_x, size_t rb_y)
    {
        if (lu_x == rb_x)
        {
            for (unsigned i = lu_y; i < rb_y; i++)
            {
                buf->cells[lu_x * buf->rows + i]->symbol = 0xB3;
            }
        }
        else if (lu_y == rb_y)
        {
            for (unsigned i = lu_x; i < rb_x; i++)
            {
                buf->cells[i * buf->rows + lu_y]->symbol = 0xC4;
            }
        }
        else
        {
            ime_bell();
            sleep(1);
        }
    }

#endif // IMECLUI_IMPLEMENTATION

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // IMECLUI_H__

#pragma once

// ANSI Escape Code Constants
#define ANSI_BOLD        "\x1b[1m"
#define ANSI_RESET       "\x1b[0m"

// True Color RGB Gradients (Dark Red to Light Red)
#define COLOR_DARK_RED   "\x1b[38;2;110;0;0m"
#define COLOR_MED_RED    "\x1b[38;2;170;0;0m"
#define COLOR_RED        "\x1b[38;2;220;0;0m"
#define COLOR_LIGHT_RED  "\x1b[38;2;255;85;85m"
#define COLOR_WHITE      "\x1b[38;2;255;255;255m"

const char* BANNER = "\n"
"\n"
ANSI_BOLD COLOR_DARK_RED  "       @@@@@@@@  @@@@@@@   @@@@@@@  \n"
ANSI_BOLD COLOR_DARK_RED  "  @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@ \n"
ANSI_BOLD COLOR_DARK_RED  "  @@!  @@!       @@!  @@@  @@!  @@@ \n"
ANSI_BOLD COLOR_MED_RED   "       !@!       !@!  @!@  !@!  @!@ \n"
ANSI_BOLD COLOR_MED_RED   "       @!!!:!    @!@  !@!  @!@!!@!  \n"
ANSI_BOLD COLOR_MED_RED   "  @!@  !!!!!:    !@!  !!!  !!@!@!   \n"
ANSI_BOLD COLOR_MED_RED   "  !!:  !!:       !!:  !!!  !!: :!!  \n"
ANSI_BOLD COLOR_LIGHT_RED "  :!:  :!:       :!:  !:!  :!:  !:! \n"
ANSI_BOLD COLOR_LIGHT_RED "   ::   :: ::::   :::: ::  ::   ::: \n"
ANSI_BOLD COLOR_LIGHT_RED "  ::   ::  : ::   :: :  :    :   : : \n"
"\n"
ANSI_BOLD COLOR_LIGHT_RED " : non-intrusive EDR-Introspection :\n"
ANSI_RESET "\n";
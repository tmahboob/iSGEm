#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include "mms_value.h"
#include "goose_publisher.h"
#include "hal_thread.h"
#include "hal_time.h"
#include <time.h>

// Function to read multiple columns of a specific row from the CSV
void readValuesFromCSV(const char* filename, int row, double* values, int numColumns) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Unable to open CSV file");
        exit(EXIT_FAILURE);
    }

    char line[512];
    int currentRow = 0;

    // Read file line by line
    while (fgets(line, sizeof(line), file)) {
        if (currentRow == row) {
            // Tokenize the row based on commas and store the values in the array
            char* token = strtok(line, ",");
            int currentColumn = 0;
            while (token != NULL && currentColumn < numColumns) {
                values[currentColumn] = atof(token);  // Convert string to double and store in the array
                token = strtok(NULL, ",");
                currentColumn++;
            }
            break;
        }
        currentRow++;
    }

    fclose(file);
}

// GOOSE Publisher Function (Modified to Use Multiple Columns from CSV)
void gooseFloatPoint68(char* interface, const char* csvFilePath, int* currentRow, int numColumns, int stNum, int sqNum) {
    LinkedList dataSetValues = LinkedList_create();
    
    CommParameters gooseCommParameters;
    gooseCommParameters.appId = 0x0001;
    gooseCommParameters.dstAddress[0] = 0x01;
    gooseCommParameters.dstAddress[1] = 0x0c;
    gooseCommParameters.dstAddress[2] = 0xcd;
    gooseCommParameters.dstAddress[3] = 0x01;
    gooseCommParameters.dstAddress[4] = 0x00;
    
    // Create an array to store multiple column values
    double values[numColumns];
    
    // Read values from the CSV for the current row
    readValuesFromCSV(csvFilePath, *currentRow, values, numColumns);

    // Loop over the columns and add them to the dataset
    for (int i = 0; i < numColumns; i++) {
        LinkedList_add(dataSetValues, MmsValue_newFloat(values[i]));
        printf("Read from csv file: %.15f\n", values[i]);
    }

    // Optionally add a bit string value to the dataset
    LinkedList_add(dataSetValues, MmsValue_newBitString(16));

    // Set destination address based on row index
    gooseCommParameters.dstAddress[5] = 0x06 + *currentRow;  // Assign different destination address based on row

    GoosePublisher publisher = GoosePublisher_create(&gooseCommParameters, interface);

    if (publisher) {
        char s[60];  
        sprintf(s, "SIPVI3p1_OperationalValues/LLN0$GO$Control_DataSet_%d", *currentRow + 3); 
        GoosePublisher_setGoCbRef(publisher, s);
        GoosePublisher_setConfRev(publisher, 10001);
        sprintf(s, "SIPVI3p1_OperationalValues/LLN0$DataSet_%d", *currentRow + 3); 
        GoosePublisher_setDataSetRef(publisher, s);
        sprintf(s, "SIP/VI3p1_OperationalValues/LLN0/Control_DataSet_%d", *currentRow + 3); 
        GoosePublisher_setGoID(publisher, s);
        GoosePublisher_setTimeAllowedToLive(publisher, 3000); 
        GoosePublisher_setStNum(publisher, stNum);

	        
	GoosePublisher_setSqNum(publisher, sqNum);
        if (GoosePublisher_publish(publisher, dataSetValues) == -1) {
            printf("Error sending message!\n");
        }
    }

    GoosePublisher_destroy(publisher);
    LinkedList_destroyDeep(dataSetValues, (LinkedListValueDeleteFunction) MmsValue_delete);

    // Increment the row index for the next call
    (*currentRow)++;
}

// Main Function (Updated to Include CSV File Path and Number of Columns)
int main(int argc, char** argv) {
    char* interface;
    char* csvFilePath;
    int numColumns = 9; // Set the number of columns you want to read from the CSV (e.g., 9 including label columns)

    if (argc > 2) {
        interface = argv[1];
        csvFilePath = argv[2];
    } else {
        printf("Usage: %s <interface> <csv_file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("Using interface %s and reading values from %s\n", interface, csvFilePath);

    // Variable to keep track of the current row
    int currentRow = 0;
    int stNum = 1;
    int sqNum = 12;

    // Loop to read and send GOOSE packet for each row
    for (int i = 0; i < 12000; i++) {  // Adjust the number of iterations based on your needs
        gooseFloatPoint68(interface, csvFilePath, &currentRow, numColumns, stNum,sqNum++);
        Thread_sleep(1000);  // Sleep for 1000ms (1 second) before reading and sending the next packet
    }

    return EXIT_SUCCESS;
}

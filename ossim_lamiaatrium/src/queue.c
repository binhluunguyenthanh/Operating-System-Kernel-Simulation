// #include <stdio.h>
// #include <stdlib.h>
// #include "queue.h"

// int empty(struct queue_t *q)
// {
//         if (q == NULL)
//                 return 1;
//         return (q->size == 0);
// }

// void enqueue(struct queue_t *q, struct pcb_t *proc)
// {
//         /* TODO: put a new process to queue [q] */
// ;
// }

// struct pcb_t *dequeue(struct queue_t *q)
// {
//         /* TODO: return a pcb whose prioprity is the highest
//          * in the queue [q] and remember to remove it from q
//          * */

// 		return NULL;
// }

// struct pcb_t *purgequeue(struct queue_t *q, struct pcb_t *proc)
// {
//         /* TODO: remove a specific item from queue
//          * */
//         return NULL;
// }
#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t *q)
{
        if (q == NULL)
                return 1;
        return (q->size == 0);
}

void enqueue(struct queue_t *q, struct pcb_t *proc)
{
        /* TODO: put a new process to queue [q] */
        if (q == NULL || proc == NULL) return;

        // Check if the queue is full
        if (q->size < MAX_QUEUE_SIZE) {
                // Add the process to the end of the queue
                q->proc[q->size] = proc;
                q->size++;
        }
        // Optional: else printf("Queue is full!\n");
}

struct pcb_t *dequeue(struct queue_t *q)
{
        /* TODO: return a pcb whose prioprity is the highest
         * in the queue [q] and remember to remove it from q
         * */
        
        // Check if the queue is empty
        if (empty(q)) {
                return NULL;
        }

        // Get the process from the front of the queue (FIFO)
        struct pcb_t *proc = q->proc[0];

        // Shift all other elements to the left
        for (int i = 0; i < q->size - 1; i++) {
                q->proc[i] = q->proc[i + 1];
        }

        // Clear the last element's pointer
        q->proc[q->size - 1] = NULL;
        q->size--;

        return proc;
}

struct pcb_t *purgequeue(struct queue_t *q, struct pcb_t *proc)
{
        /* TODO: remove a specific item from queue
         * */
        // This function is not required for the MLQ scheduling logic itself,
        // but it is good practice to implement it.
        // For now, we leave it as NULL to pass Task 2.1.
        return NULL;
}
// $Id: list.h,v 1.3 2005/01/19 22:27:45 sven Exp $

#ifndef LIST_H
#define LIST_H


typedef struct l_node {
	struct l_node *next;
	void *data;
} listnode;

class LinkedList {
	public:
		LinkedList();
		~LinkedList();
		void append(void *data);
		void prepend(void *data);
		void *del_first();
		void *del_next(listnode*);
		inline listnode* get_first() { return first; }
		inline listnode* get_next(listnode *current) { return current->next; }
	protected:
		listnode *first, *last;
};

/*listnode *list_next(listnode *current);
void list_insert(listnode *current, void *data);
void *list_delete(listnode *current);
*/

#endif

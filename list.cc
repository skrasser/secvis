// $Id: list.cc,v 1.3 2005/01/19 22:27:45 sven Exp $

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include "list.h"

LinkedList::LinkedList() : first(0), last(0) {
}

LinkedList::~LinkedList() {
	while(first) {
		del_first();
	}
}

void *LinkedList::del_first() {
	void *data = 0;
	listnode *next;
	if (first) {
		data = first->data;
		next = first->next;
		free(first);
		first = next;
		if(!first)
			last = 0;
	}
	return data;
}

void *LinkedList::del_next(listnode *current) {
	listnode *delnode;
	void *data = 0;
	if(current->next) {
		delnode = current->next;
		current->next = current->next->next;
		data = delnode->data;
		free(delnode);
	}
	return data;
}
void LinkedList::append(void *data) {
	listnode *new_node;
	if((new_node = (listnode*)malloc(sizeof(listnode)))) {
		new_node->data = data;
		new_node->next = 0;
		if(last) {
			last->next = new_node;
			last = last->next;
		} else {
			first = last = new_node;
		}
	} else {
		std::cout << "Could not store data in linked list" << std::endl;
	}
}

void LinkedList::prepend(void *data) {
	listnode *new_node;
	if((new_node = (listnode*)malloc(sizeof(listnode)))) {
		new_node->data = data;
		new_node->next = first;
		first = new_node;
		if(!last) {
			last = first;
		}
	} else {
		std::cout << "Could not store data in linked list" << std::endl;
	}
}

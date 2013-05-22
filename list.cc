// $Id: list.cc,v 1.3 2005/01/19 22:27:45 sven Exp $
using namespace std;
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
	if(new_node = (listnode*)malloc(sizeof(listnode))) {
		new_node->data = data;
		new_node->next = 0;
		if(last) {
			last->next = new_node;
			last = last->next;
		} else {
			first = last = new_node;
		}
	} else {
		cout << "Could not store data in linked list" << endl;
	}
}

void LinkedList::prepend(void *data) {
	listnode *new_node;
	if(new_node = (listnode*)malloc(sizeof(listnode))) {
		new_node->data = data;
		new_node->next = first;
		first = new_node;
		if(!last) {
			last = first;
		}
	} else {
		cout << "Could not store data in linked list" << endl;
	}
}

// some old code from the original list.c

/*
listnode *list_next(listnode *current) {
	return current->next;
}

void list_insert(listnode *current, void *data) {
	listnode *new_node;
	if(new_node = (listnode*)malloc(sizeof(listnode))) {
		new_node->data=data;
		new_node->next=current->next;
		current->next=new_node;
	} else {
		fprintf(stderr,"List: Could not insert.\n");
	}
}

listnode *list_insert_beginning(listnode *first, void *data) {
	listnode *new_node;
	if(new_node = (listnode*)malloc(sizeof(listnode))) {
		new_node->data=data;
		new_node->next=first;
		return new_node;
	} else {
		fprintf(stderr,"List: Could not insert.\n");
		return first;
	}
}

void *list_delete(listnode *current) {
	listnode *delnode;
	void *data;
	if(current->next) {
		delnode = current->next;
		current->next = current->next->next;
		data=delnode->data;
		free(delnode);
		return data;
	}
}
*/

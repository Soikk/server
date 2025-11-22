#include "rewrites.h"


static rewrite *rewrites;

void read_url_rewrites(str file){
	if(rewrites == NULL){
		init_nlist(rewrites);
	}
	int off = 0;
	while(off < file.len){
		while(off < file.len && charisspace(file.ptr[off])) off++;
		if(file.ptr[off] == '#'){
			while(off < file.len && !charislinebreak(file.ptr[off])) off++;
			continue;
		}
		rewrite rwt = {0};
		rwt.pattern = sread_delim_f(file.ptr + off, charisspace, true);
		off += rwt.pattern.len;
		while(off < file.len && charisblank(file.ptr[off])) off++;
		rwt.output.path = sread_delim_f(file.ptr + off, charisspace, true);
		off += rwt.output.path.len;
		while(off < file.len && charisblank(file.ptr[off])) off++;
		rwt.output.query = sread_delim_f(file.ptr + off, charisspace, true);
		off += rwt.output.query.len;
		while(off < file.len && !charislinebreak(file.ptr[off++]));
		if(rwt.pattern.len != 0 && rwt.output.path.len != 0){
			rwt.pattern.ptr[rwt.pattern.len] = '\0';
			rwt.output.path.ptr[rwt.output.path.len] = '\0';
			rwt.output.query.ptr[rwt.output.query.len] = '\0';
			list_push(rewrites, rwt);
		}
	}
}

void free_url_rewrites(void){
	list_free(rewrites);
}

int check_pattern(str text, str pattern, str tokens[9]){
	if(tokens == NULL){
		return 0;
	}
	int i = 0, j = 0, in = 0, ti = 0;
	for(; j < pattern.len; i += 1){
		if(i < text.len && pattern.ptr[j+in] == '<' && pattern.ptr[j+in+1] == text.ptr[i]){
			if(ti < 9 && tokens) tokens[ti++] = (str){.ptr = text.ptr+i, .len = 1};
			j += 3+in, in = 0;
		}else if(i < text.len && (pattern.ptr[j+in] == '^' || pattern.ptr[j+in] == text.ptr[i])){
			if(pattern.ptr[j] == '^' && ti < 9 && tokens) tokens[ti++] = (str){.ptr = text.ptr+i, .len = 1};
			j += 1+in, in = 0;
		}else if(i < text.len && pattern.ptr[j] == '*'){
			if(!in){
				if(ti < 9 && tokens) tokens[ti++] = (str){.ptr = text.ptr+i, .len = 0};
				in = 1;
			}
			if(ti-in < 9 && tokens) tokens[ti-in].len++;
		}else{
			if(i >= text.len && pattern.ptr[j] == '*') j++;
			else if(i >= text.len && pattern.ptr[j] == '<') j += 3;
			else return 0;
		}
	}
	return (i >= text.len);
}

str fill_blueprint(str bp, str tokens[9]){
	str r = {0};
	int rlen = 0;
	for(int i = 0; i < bp.len; i++, rlen++){
		if(bp.ptr[i] == '$') rlen += tokens[bp.ptr[++i]-'1'].len-1;
	}
	r.ptr = calloc(rlen+1, sizeof(char));
	if(r.ptr == NULL){
		return r;
	}

	for(int i = 0; i < bp.len; i++){
		if(bp.ptr[i] == '$'){
			if(++i+1 < bp.len && bp.ptr[i+1] == '<'){
				if(tokens[bp.ptr[i]-'1'].len > 0) i++;
				else while(bp.ptr[++i] != '>');
			}else{
				copy_str(r, tokens[bp.ptr[i]-'1']);
			}
		}else{
			if(bp.ptr[i] != '>') r.ptr[r.len++] = bp.ptr[i];
		}
	}
	return r;
}

/*
	Given a rewrite, with a pattern (that is checked against the url) and an output
	(that is used as an blueprintfor the output if the raw url follows the pattern)

	There is a tokens array where tokens found in the url can be stored (up to 9 tokens)

	In pattern:
		<X> optionally matches a character X and stores it in the tokens array 
		^ optionally matches any character and stores it in the tokens array
		* optionally matches a string of character until another match is found
		  or the url to match ends, and stores it in the tokens array

	In the ouput:
		$1 through $9 reference the tokens in the token array (I could make it 10 tokens tbh)
		Both the strings in the uri can access these tokens
		Referencing a token writes it to the output uri
		If theres a token before a <X>, say $3<a> that means that the character
		between the less than and greater than signs will only be written
		to the output if the token number 3 in the array exists (has length > 0)
		All other characters get outputted normally
*/
url url_rewrite(str rurl, rewrite rwt){	
	str tokens[9] = {0};
	if(!check_pattern(rurl, rwt.pattern, tokens)){
		return (url){0};
	}
	url r = {
		.path = fill_blueprint(rwt.output.path, tokens),
		.query = fill_blueprint(rwt.output.query, tokens),
	};
	if(r.path.len == 0){
		free_str(&r.path);
		free_str(&r.query);
		return (url){0};
	}
	return r;
}

url url_check(str rurl){
	str tokens[9] = {0};
	for(int i = 0; i < list_size(rewrites); i++){
		if(check_pattern(rurl, rewrites[i].pattern, tokens)){
			url r = {
				.path = fill_blueprint(rewrites[i].output.path, tokens),
				.query = fill_blueprint(rewrites[i].output.query, tokens),
			};
			if(r.path.len == 0){
				free_str(&r.path);
				free_str(&r.query);
			}
			return r;
		}
	}
	return (url){0};
}

void print_url_rewrites(void){
	int size = list_size(rewrites);
	printf("\t- rewrites:{\n");
	for(int i = 0; i < size; i++){
		printf("\t\t%.*s\t%.*s\t%.*s\n",
			rewrites[i].pattern.len, rewrites[i].pattern.ptr,
			rewrites[i].output.path.len, rewrites[i].output.path.ptr,
			rewrites[i].output.query.len, rewrites[i].output.query.ptr
		);
	}
	printf("\t}\n");
}

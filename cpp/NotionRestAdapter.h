#ifndef NOTION_REST_ADAPTER_H
#define NOTION_REST_ADAPTER_H

#include <string>
#include <map>
#include <httplib.h> // Nueva inclusión para cpp-httplib

enum class NotionAction {
    GET_DATABASE,
    QUERY_DATABASE,
    CREATE_PAGE,
    RETRIEVE_PAGE,
    UPDATE_PAGE,
    RETRIEVE_BLOCK,
    APPEND_BLOCK_CHILDREN,
    UPDATE_BLOCK,
    DELETE_BLOCK,
    SEARCH,
    GET_USERS,
    GET_USER,
    GET_ME,
    CREATE_COMMENT,
    GET_COMMENTS,
    CREATE_DATABASE // Nueva acción
};

struct NotionCommand {
    NotionAction action;
    std::map<std::string, std::string> params;
};

class NotionRestAdapter {
public:
    NotionRestAdapter();
    std::string execute(const NotionCommand& command);
    void set_api_token(const std::string& token); // Nuevo método
private:
    std::string api_token;
    std::string performRequest(const std::string& url, const std::string& method, const std::string& data);
};

#endif
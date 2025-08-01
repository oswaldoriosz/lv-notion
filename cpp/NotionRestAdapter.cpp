#include "NotionRestAdapter.h"
#include <nlohmann/json.hpp>
#include <regex>
#include <stdexcept>

NotionRestAdapter::NotionRestAdapter() {
    api_token = std::getenv("NOTION_API_TOKEN") ? std::getenv("NOTION_API_TOKEN") : "";
}

void NotionRestAdapter::set_api_token(const std::string& token) {
    api_token = token;
}

std::string NotionRestAdapter::performRequest(const std::string& url, const std::string& method, const std::string& data) {
    httplib::Client cli(url); // Crea un cliente HTTP/HTTPS

    // Configura los headers
    httplib::Headers headers;
    if (!api_token.empty()) {
        headers.emplace("Authorization", "Bearer " + api_token);
    }
    headers.emplace("Notion-Version", "2022-06-28");
    headers.emplace("Content-Type", "application/json");

    // Realiza la solicitud según el método
    std::string response;
    if (method == "POST") {
        auto res = cli.Post("/", headers, data, "application/json");
        if (res && res->status == 200) {
            response = res->body;
        } else if (res) {
            throw std::runtime_error("HTTP error: " + std::to_string(res->status));
        } else {
            throw std::runtime_error("Failed to connect to Notion API");
        }
    } else if (method == "PATCH") {
        auto res = cli.Patch("/", headers, data, "application/json");
        if (res && res->status == 200) {
            response = res->body;
        } else if (res) {
            throw std::runtime_error("HTTP error: " + std::to_string(res->status));
        } else {
            throw std::runtime_error("Failed to connect to Notion API");
        }
    } else if (method == "DELETE") {
        auto res = cli.Delete("/", headers);
        if (res && res->status == 200) {
            response = res->body;
        } else if (res) {
            throw std::runtime_error("HTTP error: " + std::to_string(res->status));
        } else {
            throw std::runtime_error("Failed to connect to Notion API");
        }
    } else { // GET u otros métodos
        auto res = cli.Get("/", headers);
        if (res && res->status == 200) {
            response = res->body;
        } else if (res) {
            throw std::runtime_error("HTTP error: " + std::to_string(res->status));
        } else {
            throw std::runtime_error("Failed to connect to Notion API");
        }
    }

    try {
        nlohmann::json json_response = nlohmann::json::parse(response);
        return response;
    } catch (const nlohmann::json::parse_error& e) {
        nlohmann::json error = {
            {"object", "error"},
            {"status", 0}, // No tenemos el código HTTP directamente aquí, ajusta si es necesario
            {"code", "invalid_response"},
            {"message", "Respuesta de la API no es un JSON válido: " + response}
        };
        return error.dump();
    }
}

std::string NotionRestAdapter::execute(const NotionCommand& command) {
    std::string url = "https://api.notion.com/v1/";
    std::string method = "GET";
    std::string data;

    // Verificar si hay un token en los parámetros
    if (!command.params.empty() && command.params.find("token") != command.params.end()) {
        set_api_token(command.params.at("token"));
    }

    switch (command.action) {
        case NotionAction::GET_DATABASE:
            url += "databases/" + command.params.at("database_id");
            break;
        case NotionAction::QUERY_DATABASE:
            url += "databases/" + command.params.at("database_id") + "/query";
            method = "POST";
            try {
                nlohmann::json filter_json = nlohmann::json::parse(command.params.at("filter"));
                nlohmann::json body = {{"filter", filter_json}};
                data = body.dump();
            } catch (const nlohmann::json::parse_error& e) {
                throw std::runtime_error("Filtro JSON inválido: " + std::string(e.what()));
            }
            break;
        case NotionAction::CREATE_PAGE:
            url += "pages";
            method = "POST";
            {
                std::string parent_id = command.params.count("parent_id") ? command.params.at("parent_id") : 
                               (command.params.count("database_id") ? command.params.at("database_id") : "");
                std::regex uuid_regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
                if (!std::regex_match(parent_id, uuid_regex)) {
                    throw std::runtime_error("parent_id o database_id debe ser un UUID válido");
                }
                std::string title = command.params.at("title");
                std::string content = command.params.count("content") ? command.params.at("content") : "";
                data = R"({"parent": {"database_id": ")" + parent_id + R"("}, "properties": {"Name": {"title": [{"text": {"content": ")" + title + R"("}}]}})";
                if (!content.empty()) {
                    data += R"(,"children": [{"object": "block", "type": "paragraph", "paragraph": {"text": [{"type": "text", "text": {"content": ")" + content + R"("}}]}}])";
                }
            }
            break;
        case NotionAction::RETRIEVE_PAGE:
            url += "pages/" + command.params.at("page_id");
            break;
        case NotionAction::UPDATE_PAGE:
            url += "pages/" + command.params.at("page_id");
            method = "PATCH";
            data = command.params.at("properties");
            break;
        case NotionAction::RETRIEVE_BLOCK:
            url += "blocks/" + command.params.at("block_id");
            break;
        case NotionAction::APPEND_BLOCK_CHILDREN:
            url += "blocks/" + command.params.at("block_id") + "/children";
            method = "PATCH";
            data = command.params.at("children");
            break;
        case NotionAction::UPDATE_BLOCK:
            url += "blocks/" + command.params.at("block_id");
            method = "PATCH";
            data = command.params.at("block_data");
            break;
        case NotionAction::DELETE_BLOCK:
            url += "blocks/" + command.params.at("block_id");
            method = "DELETE";
            break;
        case NotionAction::SEARCH:
            url += "search";
            method = "POST";
            data = "{\"query\": \"" + (command.params.count("query") ? command.params.at("query") : (command.params.count("object") ? command.params.at("object") : "")) + "\"}";
            break;
        case NotionAction::GET_USERS:
            url += "users";
            break;
        case NotionAction::GET_USER:
            url += "users/" + command.params.at("user_id");
            break;
        case NotionAction::GET_ME:
            url += "users/me";
            break;
        case NotionAction::CREATE_COMMENT:
            url += "comments";
            method = "POST";
            data = command.params.at("comment_data");
            break;
        case NotionAction::GET_COMMENTS:
            url += "comments?page_id=" + command.params.at("page_id");
            break;
        case NotionAction::CREATE_DATABASE:
            url += "databases";
            method = "POST";
            {
                std::string parent_page_id = command.params.at("parent_page_id");
                std::regex uuid_regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
                if (!std::regex_match(parent_page_id, uuid_regex)) {
                    throw std::runtime_error("parent_page_id debe ser un UUID válido");
                }
                std::string title = command.params.at("title");
                data = R"({"parent": {"page_id": ")" + parent_page_id + R"("},"title": [{"type": "text", "text": {"content": ")" + title + R"("}}],"properties": {"Name": {"title": {}}}})";
            }
            break;
        default:
            throw std::runtime_error("Unsupported NotionAction");
    }

    return performRequest(url, method, data);
}
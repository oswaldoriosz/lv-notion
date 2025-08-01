#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "NotionRestAdapter.h"

namespace py = pybind11;

PYBIND11_MODULE(notion_hex, m) {
    py::class_<NotionRestAdapter>(m, "NotionRestAdapter")
        .def(py::init<>())
        .def("execute", [](NotionRestAdapter& self, py::dict py_command) {
            NotionCommand cmd;
            if (!py_command.contains("action")) {
                throw py::value_error("El comando debe contener una clave 'action'");
            }
            cmd.action = static_cast<NotionAction>(py_command["action"].cast<int>());

            if (!py_command.contains("params")) {
                throw py::value_error("El comando debe contener una clave 'params'");
            }
            py::dict params_dict = py_command["params"].cast<py::dict>();
            std::map<std::string, std::string> params;
            for (const auto& item : params_dict) {
                std::string key = py::cast<std::string>(item.first);
                std::string value = py::cast<std::string>(item.second);
                params[key] = value;
            }
            // Extraer el token del nivel raíz y añadirlo a params
            if (py_command.contains("token")) {
                params["token"] = py::cast<std::string>(py_command["token"]);
            }
            cmd.params = params;

            return self.execute(cmd);
        });

    py::enum_<NotionAction>(m, "NotionAction")
        .value("GET_DATABASE", NotionAction::GET_DATABASE)
        .value("QUERY_DATABASE", NotionAction::QUERY_DATABASE)
        .value("CREATE_PAGE", NotionAction::CREATE_PAGE)
        .value("RETRIEVE_PAGE", NotionAction::RETRIEVE_PAGE)
        .value("UPDATE_PAGE", NotionAction::UPDATE_PAGE)
        .value("RETRIEVE_BLOCK", NotionAction::RETRIEVE_BLOCK)
        .value("APPEND_BLOCK_CHILDREN", NotionAction::APPEND_BLOCK_CHILDREN)
        .value("UPDATE_BLOCK", NotionAction::UPDATE_BLOCK)
        .value("DELETE_BLOCK", NotionAction::DELETE_BLOCK)
        .value("SEARCH", NotionAction::SEARCH)
        .value("GET_USERS", NotionAction::GET_USERS)
        .value("GET_USER", NotionAction::GET_USER)
        .value("GET_ME", NotionAction::GET_ME)
        .value("CREATE_COMMENT", NotionAction::CREATE_COMMENT)
        .value("GET_COMMENTS", NotionAction::GET_COMMENTS)
        .value("CREATE_DATABASE", NotionAction::CREATE_DATABASE); // Nueva acción
}
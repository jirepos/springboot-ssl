
package com.jirepos.autoconfig.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/fm")
public class FreemarkerController {
    
    @RequestMapping("/index")
    public String index() {
        return "/free";
    }
}

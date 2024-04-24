package com.xd.hufei.common;

import org.apache.log4j.Logger;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * @author hufei
 * @date 2024/04/23
 * @desc 管理配置文件的类，使用单线程下的单例设计
 * */
public class PropertiesManager {

    private static PropertiesManager instance;

    private Map<String,String> properties;

    private final Logger logger = Logger.getLogger(PropertiesManager.class);

    private static final String[] PATHS = {
            "/connection.properties","/vxipmi.properties"
    };

    private PropertiesManager(){
        properties = new HashMap<>();
        for(String path : PATHS){
            loadProperties(path);
        }
    }

    public static PropertiesManager getInstance() {
        if (instance == null) {
            instance = new PropertiesManager();
        }
        return instance;
    }
    private void loadProperties(String name) {
        try {
            Properties properties = new Properties();
            properties.load(getClass().getResourceAsStream(name));

            for (Object key : properties.keySet()) {
                this.properties.put(key.toString(), properties.getProperty(key.toString()));
            }

        } catch (IOException e) {
            logger.error(e.getMessage(), e);
        }
    }

    public String getProperty(String key) {
        logger.info("Getting " + key + ": " + properties.get(key));
        return properties.get(key);
    }

}

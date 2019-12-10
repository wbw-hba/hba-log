package cn.hba.audit.flume.interceptor;

import javax.script.*;

/**
 * @author liuk
 */
public class JsDynamicCompiler {


    private volatile static JsDynamicCompiler ins = null;

    public static JsDynamicCompiler get() {
        if (null == ins) {
            synchronized (JsDynamicCompiler.class) {
                if (null == ins) {
                    ins = new JsDynamicCompiler();
                    ins.init();
                }
            }
        }
        return ins;
    }

    private ScriptEngine scriptEngine;

    private JsDynamicCompiler() {

    }

    private void init() {
        try {
            ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
            scriptEngine = scriptEngineManager.getEngineByName("nashorn");
        } catch (Exception e) {
            throw new RuntimeException("当前jdk不支持 nashorn引擎", e);
        }
    }

    public <T> T compileAndBuild(Class<T> interfaceClass, String jsFunction) {
        T result;
        try {
            CompiledScript sc = ((Compilable) scriptEngine).compile(jsFunction);
            sc.eval();
            Invocable invocable = (Invocable) sc.getEngine();
            result = invocable.getInterface(interfaceClass);
        } catch (Throwable e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        return result;
    }
}

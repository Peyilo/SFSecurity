package org.peyilo.sfsecurity;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

public class SfacgJni extends AbstractJni {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final Debugger debugger;
    private final Backend backend;

    public SfacgJni() {
        emulator = AndroidEmulatorBuilder.for32Bit()
                .setProcessName("org.peyilo.sfsecurity")
                .build();
        final Memory memory = emulator.getMemory();
        final String dir = "src/main/resources/" + "version3" + "/";
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File(dir + "boluobao.apk"));
        DalvikModule dalvikModule = vm.loadLibrary(new File(dir + "libsfdata.so"), false);
        module = dalvikModule.getModule();  // 获得so操作句柄
        saveTraceCode(dir + "log.txt");                 // 保存汇编代码执行过程到txt文件中
        vm.setJni(this);
        // vm.setVerbose(true);             // 打印信息是否详细
        dalvikModule.callJNI_OnLoad(emulator);
        debugger = emulator.attach();
        backend = emulator.getBackend();
    }

    private void saveTraceCode(String path) {
        try {
            PrintStream traceStream = new PrintStream(new FileOutputStream(path), true);
            emulator.traceCode(module.base, module.base + module.size).setRedirect(traceStream);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public String getSFSecurity(String deviceToken) {
        System.out.println("\ngetSFSecurity:");

        // JNI签名约定：Java_com_sf_security_AuthConfig_getSFSecurity对应的函数签名为
        // Java_com_sf_security_AuthConfig_getSFSecurity(JNIEnv *env, jobject obj, ...)
        // 在java中的函数签名如下
        // private native String getSFSecurity(Context context, String str);
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());       // 第一个参数为JNIEnv指针
        // 第二个参数，实例方法是jobject，静态方法是jclazz，直接填0，一般用不到。
        list.add(0);
        // getSFSecurity(Context context, String str)对应的两个参数
        DvmObject<?> dvmObject = vm.resolveClass("android/content/Context").newObject(null);
        list.add(vm.addLocalObject(dvmObject));
        list.add(vm.addLocalObject(new StringObject(vm, deviceToken)));
        debug();

        // +1 thumb模式 arm不用加
        Number number = module.callFunction(emulator, 0xAB3C + 1, list.toArray());
        return vm.getObject(number.intValue()).getValue().toString();
    }

    // 添加断点进行调试
    private void debug() {
        try {
            debugger.addBreakPoint(module, 0xb4b4 + 1, (emulator1, address) -> {
                System.out.println("Debugger:");
                byte[] bytes = backend.mem_read(0xbffff3b9L, 64);
                String s = new String(bytes);
                System.out.println(s);
                System.out.println(Arrays.toString(bytes));
                return true;
            });
        }catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        // System.out.println(signature);
        if (signature.equals("java/util/UUID->randomUUID()Ljava/util/UUID;")) {
            UUID uuid = UUID.randomUUID();
            System.out.println("randomUUID: " + uuid);
            return dvmClass.newObject(uuid);
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        //System.out.println(signature);
        if (signature.equals("java/util/UUID->toString()Ljava/lang/String;")) {
            String uuid = dvmObject.getValue().toString();
            System.out.println("toString: " + uuid);
            return new StringObject(vm, uuid);
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

}

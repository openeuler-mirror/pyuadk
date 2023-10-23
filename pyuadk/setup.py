from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    
    Extension("pyuadk.pywd", 
              ["pyuadk/pywd.pyx",
               "uadk/v1/wd_rsa.c", 
               "uadk/v1/wd_cipher.c", 
               "uadk/v1/wd.c", 
                "uadk/v1/wd_util.c",
                "uadk/v1/wd_adapter.c",
                "uadk/v1/wd_sgl.c",
                "uadk/v1/wd_bmm.c",
                "uadk/v1/wd_ecc.c",
                "uadk/v1/drv/dummy_drv.c",
                "uadk/v1/drv/hisi_qm_udrv.c",
                "uadk/v1/drv/hisi_rng_udrv.c",
                "uadk/v1/drv/hisi_hpre_udrv.c",
                "uadk/v1/drv/hisi_sec_udrv.c",
                "uadk/v1/drv/hisi_zip_udrv.c"
               ], 
              include_dirs=["uadk/"]),

    Extension("pyuadk.pywd_cipher", 
              ["pyuadk/pywd_cipher.pyx",
               "uadk/v1/wd_rsa.c", 
               "uadk/v1/wd_cipher.c", 
               "uadk/v1/wd.c", 
                "uadk/v1/wd_util.c",
                "uadk/v1/wd_adapter.c",
                "uadk/v1/wd_sgl.c",
                "uadk/v1/wd_bmm.c",
                "uadk/v1/wd_ecc.c",
                "uadk/v1/drv/dummy_drv.c",
                "uadk/v1/drv/hisi_qm_udrv.c",
                "uadk/v1/drv/hisi_rng_udrv.c",
                "uadk/v1/drv/hisi_hpre_udrv.c",
                "uadk/v1/drv/hisi_sec_udrv.c",
                "uadk/v1/drv/hisi_zip_udrv.c"
               ], 
              include_dirs=["uadk/"]),
    Extension("pyuadk.pywd_digest",
            ["pyuadk/pywd_digest.pyx", 
             "uadk/v1/wd_digest.c",
             "uadk/v1/wd_rsa.c", 
               "uadk/v1/wd_cipher.c", 
               "uadk/v1/wd.c", 
                "uadk/v1/wd_util.c",
                "uadk/v1/wd_adapter.c",
                "uadk/v1/wd_sgl.c",
                "uadk/v1/wd_bmm.c",
                "uadk/v1/wd_ecc.c",
                "uadk/v1/drv/dummy_drv.c",
                "uadk/v1/drv/hisi_qm_udrv.c",
                "uadk/v1/drv/hisi_rng_udrv.c",
                "uadk/v1/drv/hisi_hpre_udrv.c",
                "uadk/v1/drv/hisi_sec_udrv.c",
                "uadk/v1/drv/hisi_zip_udrv.c"
             ],
            include_dirs=["uadk/"]),
    Extension("pyuadk.pywd_rsa",
               [
                "pyuadk/pywd_rsa.pyx", 
                "uadk/v1/wd_rsa.c", 
                "uadk/v1/wd.c", 
                "uadk/v1/wd_util.c",
                "uadk/v1/wd_adapter.c",
                "uadk/v1/wd_sgl.c",
                "uadk/v1/wd_bmm.c",
                "uadk/v1/wd_ecc.c",
                "uadk/v1/drv/dummy_drv.c",
                "uadk/v1/drv/hisi_qm_udrv.c",
                "uadk/v1/drv/hisi_rng_udrv.c",
                "uadk/v1/drv/hisi_hpre_udrv.c",
                "uadk/v1/drv/hisi_sec_udrv.c",
                "uadk/v1/drv/hisi_zip_udrv.c"
                ], 
               include_dirs=["uadk/"])
    # 添加其他Cython文件的Extension对象
]

setup(
    name="pyuadk",
    ext_modules=cythonize(extensions),
    
    # package_data={'pyuadk': ['build/lib.linux-aarch64-3.9/pywd_cipher.cpython-39-aarch64-linux-gnu.so']},
)

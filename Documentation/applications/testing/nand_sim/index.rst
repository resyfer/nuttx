======================================
``nand`` - NAND Flash Device Simulator
======================================

In order to test the filesystems that work with NAND flash devices in a
simulator, this exists to provide a virtual NAND flash device, along with its
driver, to allow manual (or scripted) testing, as well as to provide an
option to log the various actions performed under-the-hood along with the
state of the device, which includes the read, write and erase counts of each
page in the device.

Structure of NAND Flash
=======================

Most NAND flashes share a common interface, specified by the
`Open NAND Flash Interface (ONFI) <https://www.onfi.org/>`_.

The important part from it, required in this context, is that a NAND Flash is
divided into a lot of blocks. And each blocks are divided into a lot of
pages.

Here's the pecular bit. If you want to erase a page, you need to erase
the *entire* block that it is part of, ie. blocks are the smallest erasable
units in a NAND flash. However, a page is the smallest unit to which you can
write data, or read data from.

Why would you need erase operation? The Program/ Erase (P/E) cycle states
that a page (and thus its block) need to be erased first before data can be
written to it (Erase-Before-Write).

Each page has a data area, and a spare area. Depending on the data area's
size, the spare area may have different structures (schemes). All the
required schemes are defined in ``/drivers/mtd/mtd_nandscheme.c`` (in
the ``g_nand_sparescheme*`` structures).

Due to the nature of NAND flash, upon testing, a manufaturer may decide that
a certain block fails some test(s), and mark it as a **bad block** by
writing a certain value in a certain position in the spare area (depends on
data area's size, and thus, the spare area's scheme) of every page in it.

.. NOTE::
    * While certain blocks may *still work* even if they are marked as bad,
      it's inadvisable to store any data in it.

    * The spare data is the **only** record of a block being bad or not.
      Please do not erase it.

    * Certain blocks may become bad after continuous usage, and would need
      to be marked as such by either the filesystem or the driver.

Currently, this simulator supports only 512 B sized pages, which means it
will follow  the ``g_nand_sparescheme512`` scheme for its spare area, and
thus have a bad block marker at index ``5``.

If a block is *not* bad, it contains a value of ``0xff`` in the place of a
bad block marker. Any other value denote it's a bad block.

RAM to Device
=============

Since this is an emulation, RAM of the host running the simulator is used
to create the device. While the speed of operations won't be even close to
the original, this being in the RAM, which works multitudes faster than
actual device, the functionality on the other hand has been kept consistent
to the utmost.

First, ``/include/nuttx/mtd/nand.h`` has a structure ``struct nand_dev_s``
defining a raw NAND MTD device (lowest level). Its field ``nand_dev_s->raw``
is of type ``struct nand_raw_s *`` (defined in
``include/nuttx/mtd/nand_raw.h``), and this is what will hold the methods
for the raw device. There are primarily 3 methods that need to be looked
into:

* eraseblock
* rawread
* rawwrite

While in real devices, the spare area follows the data area (in most schemes)
, since this is virtual, we can get away with keeping the two into two
separate arrays, namely ``g_nand_sim_flash_data`` and
``g_nand_sim_flash_spare`` for data and spare respectively. Each array
has as many elements as number of pages in the device.

Conforming to the functionality of NAND flashes, these three were implemented
as ``nand_sim_*`` in ``apps/testing/nand_sim/nand_sim_raw.c``.

As the spare areas has some spare bytes we can use, some space is used as
counters for the reads/writes/erases each page faces, thus giving a clear
picture of wear of the virtual device to the tester.

.. NOTE::
    ECC extension has not been implemented yet.

Apart from these methods, the raw device structure requires a definition of
the model of the device ``nand_dev_s->model`` (``struct nand_model_s``
as defined in ``/include/nuttx/mtd/nand_model.h``) (``devid`` can be any
unique device ID).

With this raw device (lower half of the device driver) ready, it needs to be
initialized as a NAND MTD device, which can be done using the
``nand_raw_initialize`` (which, unlike the ``nand_initialize`` function,
does not probe for the existence of such a device, which is required due to
this device being virtual), which gives us our upper half of the device
driver.

The upper half contains methods defined in ``/drivers/mtd/mtd_nand.c``
which in turn use the custom lower half methods provided to it in the
form of the raw device.

Wrapper Over Upper Half
=======================

Each driver's upper half needs to be registered with NuttX before it can
appear in the list of devices (in ``/dev``). Instead of the previously
acquired upper-half, we'll be registering a wrapper over it, to improve
logging. Wrappers over the various functions of this are defined.
These methods are part of ``struct mtd_dev_s`` (defined in
``include/nuttx/mtd/mtd.h``), and are namely:

* erase
* bread
* bwrite
* ioctl
* isbad
* markbad

Our wrapper is an MTD device which is represented by ``struct mtd_dev_s``,
but more specifically, it is a NAND MTD device, which is represented by
``struct nand_dev_s``. Due to how it is defined, ``struct mtd_dev_s`` forms
the very start of ``struct nand_dev_s``, and hence they can be type-casted
to each other (provided required memory is accessible).

Thus, in the ``wrapper_init`` function, ``g_nand_sim_mtd_wrapper`` is
initialized with the size of ``struct nand_dev_s``, despite it being
required to be of type ``struct mtd_dev_s`` by the unified interface. This
allows us to type-caste ``wrapper_init`` to ``struct nand_dev_s``, define
our own wrapper methods, as well as attach the raw device to it
(``nand_raw_initialize`` does this internally as well).

Wrapper Methods
---------------

These wrapper methods just log the infomation about it being called, and
directly pass the parameters to the actual upper half (the methods defined
in ``drivers/mtd/mtd_nand.c``).

Registering Device & Daemon
===========================

This wrapper is then registered using ``register_mtddriver``, and this
whole thing is converted to be a daemon, so that the device can keep running
in the baackground.

Making it a daemon is achieved by using ``fork()``, killing the parent, and
using ``daemon()`` in child.

Stats & Logging
===============

There are two files, which will be located at ``/tmp/nand_log`` and
``/tmp/nand_stat``, which contain the logs of method calls and the wear
status of the device respectively. If ``CONFIG_TESTING_NAND_SIM_DEBUG``
is set to 1, then instead of ``/tmp/nand_log``, it will be logged out to
the console, and this file won't be created.

Since updating status of the entire device may be costly, signals are used
to indicate when you want the status to be written. Providing a signal of
``10`` to this using ``kill`` command will make this application write the
updated device status. Similarly, a signal of ``12`` will flush its logs.

Known Issues
============

* There is a limit to the number of pages that are being written to the
  ``/tmp/nand_stat``. Currently it's observed to be 4096 pages (each page
  has its stats in a separate line), which would be a 2MB device with 512B
  page size.
* Logging to file only outputs a single line in ``/tmp/nand_log`` and an, even
  additional incomplete line with flush.
* Can't view the ``/tmp/nand_log`` file while the application is running. It
  needs to be closed first.
